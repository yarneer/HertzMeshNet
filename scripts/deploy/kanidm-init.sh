#!/usr/bin/env bash
# 生产 Kanidm 初始化（docs/runbook.md §5）：
#   恢复内置管理员 → 创建 hznet_admins / hznet_users 组 → 创建第一个 User 并
#   设口令 → 创建 OAuth2 客户端 hznet-coord（回调 https://coord.<域名>/oidc/
#   callback 与 Admin Console 的 /admin/oidc/callback）→ 把 --oidc-* 连同
#   client secret 写进 /etc/default/hz-coord 并
#   重启 hz-coord。
# API 走向复用 scripts/test/kanidm/setup.sh 对 Kanidm 1.8 的实测结论：
#   person 口令只能走 credential-update 会话 API；oauth2 写操作需要特权会话。
# 前提：certs.sh 已换正式证书（本脚本用系统 CA 校验 auth.<域名>）。
# 用法：kanidm-init.sh --domain <域名> --admin-name <名字> [--no-systemctl]
# 部署脚本依赖 bash；被 /bin/sh（Debian 的 dash 等）执行时在 set -o pipefail
# 前给出明确指引，而不是 "Illegal option -o pipefail"。
[ -n "${BASH_VERSION:-}" ] || { echo "本脚本需要 bash 运行：sudo bash $0 <参数>" >&2; exit 1; }
set -euo pipefail

DOMAIN=""
ADMIN_NAME=""
ADMIN_DISPLAY=""
NO_SYSTEMCTL=0

usage() {
  cat >&2 <<'USAGE'
用法: kanidm-init.sh --domain <域名> --admin-name <登录名> [--admin-displayname "显示名"] [--no-systemctl]
USAGE
  exit 1
}
die() { echo "kanidm-init: ${1}" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:?--domain 需要值}" ; shift 2 ;;
    --admin-name) ADMIN_NAME="${2:?--admin-name 需要值}" ; shift 2 ;;
    --admin-displayname) ADMIN_DISPLAY="${2:?--admin-displayname 需要值}" ; shift 2 ;;
    --no-systemctl) NO_SYSTEMCTL=1 ; shift ;;
    -h|--help) usage ;;
    *) echo "未知参数：${1}" >&2 ; usage ;;
  esac
done
[ -n "${DOMAIN}" ] && [ -n "${ADMIN_NAME}" ] || usage
[ "$(id -u)" = "0" ] || die "需要 root（sudo）运行"
command -v kanidmd >/dev/null 2>&1 || die "缺少 kanidmd，先按 runbook §5 安装"
command -v kanidm >/dev/null 2>&1 || die "缺少 kanidm CLI，先按 runbook §5 安装"
command -v python3 >/dev/null 2>&1 || die "缺少 python3（apt-get install python3）"
command -v curl >/dev/null 2>&1 || die "缺少 curl"
[ "${ADMIN_NAME}" = "admin" ] && die "admin 是 Kanidm 内置账号，请另取一个登录名"

SYSTEMCTL=1
if [ "${NO_SYSTEMCTL}" = "1" ] || ! command -v systemctl >/dev/null 2>&1; then
  SYSTEMCTL=0
fi
sys() {
  if [ "${SYSTEMCTL}" = "1" ]; then
    systemctl "$@"
  else
    echo "[skip-systemctl] systemctl $*"
  fi
}

ISSUER="https://auth.${DOMAIN}/oauth2/openid/hznet-coord"
REDIRECT="https://coord.${DOMAIN}/oidc/callback"
# Admin Console 的 OIDC 回调。与 hz-coord 里 admin_redirect_uri 的路径一致，
# 严格回调模式下两条都要登记，否则浏览器登录 Admin Console 会被 Kanidm 拒绝。
ADMIN_REDIRECT="https://coord.${DOMAIN}/admin/oidc/callback"
URL="https://auth.${DOMAIN}"

echo "==> 等待 Kanidm 就绪（${URL}/status）"
ready=0
for _ in $(seq 1 60); do
  if curl -fsS "${URL}/status" | grep -q true; then ready=1; break; fi
  sleep 1
done
[ "${ready}" = "1" ] \
  || die "Kanidm 未就绪：systemctl status kanidm；若证书仍是占位自签，先运行 certs.sh"

CACHE_BASE="/var/lib/hznet-deploy/kanidm-cache"
mkdir -p "${CACHE_BASE}/admin" "${CACHE_BASE}/idm"
kcli() {
  local cache="$1"; shift
  HOME="${CACHE_BASE}/${cache}" KANIDM_URL="${URL}" kanidm "$@"
}

echo "==> 恢复内置管理员口令并登录"
ADMIN_PW=$(kanidmd recover-account admin 2>/dev/null \
  | grep -o 'new_password: "[^"]*"' | cut -d'"' -f2)
IDM_PW=$(kanidmd recover-account idm_admin 2>/dev/null \
  | grep -o 'new_password: "[^"]*"' | cut -d'"' -f2)
[ -n "${ADMIN_PW}" ] && [ -n "${IDM_PW}" ] || die "recover-account 失败"
kcli admin login --name admin --password "${ADMIN_PW}" >/dev/null
kcli idm login --name idm_admin --password "${IDM_PW}" >/dev/null

# 幂等辅助：已存在（重复值）不算失败。
ok_or_exists() {
  local out="$1"
  if echo "${out}" | grep -qiE 'uplicate|0008|already exist'; then
    return 0
  fi
  return 1
}

echo "==> 创建组与第一个 User（${ADMIN_NAME}）"
[ -n "${ADMIN_DISPLAY}" ] || ADMIN_DISPLAY="HzNet Admin ${ADMIN_NAME}"
out=$(kcli idm group create hznet_admins 2>&1) || ok_or_exists "${out}" || die "group create hznet_admins 失败：${out}"
out=$(kcli idm group create hznet_users 2>&1) || ok_or_exists "${out}" || die "group create hznet_users 失败：${out}"
out=$(kcli idm person create "${ADMIN_NAME}" "${ADMIN_DISPLAY}" 2>&1) || ok_or_exists "${out}" || die "person create ${ADMIN_NAME} 失败：${out}"
out=$(kcli idm group add-members hznet_admins "${ADMIN_NAME}" 2>&1) || ok_or_exists "${out}" || die "加入 hznet_admins 失败：${out}"
out=$(kcli idm group add-members hznet_users "${ADMIN_NAME}" 2>&1) || ok_or_exists "${out}" || die "加入 hznet_users 失败：${out}"
# 单因子口令可提交：内置策略放宽到 any（生产如需 MFA 请自行调回并重新登录）。
kcli idm group account-policy credential-type-minimum idm_all_persons any >/dev/null
# OAuth2 客户端管理权交给第一个 User（下面用它的特权会话建客户端）。
out=$(kcli idm group add-members idm_oauth2_admins "${ADMIN_NAME}" 2>&1) || ok_or_exists "${out}" || die "加入 idm_oauth2_admins 失败：${out}"

ADMIN_LOGIN_PW="$(openssl rand -base64 15)"

# 经 credential-update 会话 API 设口令（Kanidm CLI 无非交互 set-password）；
# 口令不满足质量检查时 update 会拒绝提交，这里显式失败。
set_password() {
  local user="$1" password="$2" token sess update commit
  token=$(kcli idm person credential create-reset-token "${user}" 2>/dev/null \
    | grep 'use-reset-token' | awk '{print $NF}')
  [ -n "${token}" ] || die "create-reset-token 失败（${user}）"
  sess=$(curl -fsS -X POST "${URL}/v1/credential/_exchange_intent" \
    -H 'Content-Type: application/json' -d "\"${token}\"" \
    | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)[0]))') \
    || die "兑换重置意图失败（${user}）"
  update=$(curl -fsS -X POST "${URL}/v1/credential/_update" -H 'Content-Type: application/json' \
    -d "[{\"password\":\"${password}\"},${sess}]") \
    || die "口令更新会话失败（${user}）"
  echo "${update}" | grep -q '"can_commit":true' \
    || { echo "口令被质量检查拒绝（${user}）：${update}" >&2; exit 1; }
  commit=$(curl -fsS -X POST "${URL}/v1/credential/_commit" -H 'Content-Type: application/json' \
    -d "${sess}") || die "口令提交失败（${user}）"
  [ "${commit}" = "null" ] || die "口令提交异常（${user}）：${commit}"
}

echo "==> 设置 ${ADMIN_NAME} 的登录口令"
set_password "${ADMIN_NAME}" "${ADMIN_LOGIN_PW}"

# 口令登录 → 特权升级 → 输出特权 bearer（oauth2 写操作需要）。
privileged_token() {
  local user="$1" password="$2"
  python3 - "${URL}" "${user}" "${password}" <<'PYEOF'
import json, subprocess, sys, tempfile, os

issuer, user, password = sys.argv[1], sys.argv[2], sys.argv[3]
jar = tempfile.NamedTemporaryFile(delete=False)
jar.close()

def post(path, body, bearer=None):
    args = ['curl', '-fsS', '-b', jar.name, '-c', jar.name, '-X', 'POST',
            issuer + path, '-H', 'Content-Type: application/json',
            '-d', json.dumps(body) if not isinstance(body, str) else '"%s"' % body]
    if bearer:
        args += ['-H', 'Authorization: Bearer ' + bearer]
    return subprocess.run(args, capture_output=True, text=True).stdout

try:
    state = json.loads(post('/v1/auth', {"step": {"init2": {
        "username": user, "issue": "token", "privileged": False}}}))['state']
    assert 'choose' in state, state
    state = json.loads(post('/v1/auth', {"step": {"begin": "password"}}))['state']
    assert 'continue' in state, state
    token = json.loads(post('/v1/auth', {"step": {"cred": {"password": password}}}))['state'].get('success')
    if not token:
        sys.exit('口令登录未取得 token')
    state = json.loads(post('/v1/reauth', 'token', bearer=token))['state']
    assert 'continue' in state, state
    privileged = json.loads(post('/v1/auth', {"step": {"cred": {"password": password}}}, bearer=token))['state'].get('success')
    if not privileged:
        sys.exit('特权升级失败')
    print(privileged)
finally:
    os.unlink(jar.name)
PYEOF
}

api() {
  local method="$1" path="$2" token="$3" body="${4:-}"
  if [ -n "${body}" ]; then
    curl -fsS -X "${method}" "${URL}${path}" -H "Authorization: Bearer ${token}" \
      -H 'Content-Type: application/json' -d "${body}" -w '\n%{http_code}'
  else
    curl -fsS -X "${method}" "${URL}${path}" -H "Authorization: Bearer ${token}" \
      -w '\n%{http_code}'
  fi
}

echo "==> 创建 OAuth2 客户端 hznet-coord（回调 ${REDIRECT} 与 ${ADMIN_REDIRECT}）"
PRIV=$(privileged_token "${ADMIN_NAME}" "${ADMIN_LOGIN_PW}")
[ -n "${PRIV}" ] || die "未取得特权会话"
out=$(api POST /v1/oauth2/_basic "${PRIV}" \
  '{"attrs":{"name":["hznet-coord"],"displayname":["HzNet Coordination Server"],"oauth2_rs_origin_landing":["https://coord.'"${DOMAIN}"'/"],"oauth2_strict_redirect_uri":["true"]}}' 2>&1) \
  || ok_or_exists "${out}" || die "oauth2 create 失败：${out}"
# 回调地址走 PATCH（实测 _attr 追加端点对机密客户端返回 nomatchingentries）。
out=$(api PATCH /v1/oauth2/hznet-coord "${PRIV}" \
  "{\"attrs\":{\"oauth2_rs_origin\":[\"${REDIRECT}\",\"${ADMIN_REDIRECT}\"]}}" 2>&1) \
  || die "注册回调失败：${out}"
out=$(api POST "/v1/oauth2/hznet-coord/_scopemap/hznet_users" "${PRIV}" \
  '["openid","profile","groups"]' 2>&1) \
  || ok_or_exists "${out}" || die "scopemap 失败：${out}"
out=$(api PATCH /v1/oauth2/hznet-coord "${PRIV}" \
  '{"attrs":{"oauth2_prefer_short_username":["true"]}}' 2>&1) \
  || die "设置短用户名偏好失败：${out}"
SECRET=$(api GET /v1/oauth2/hznet-coord/_basic_secret "${PRIV}" | head -1 | tr -d '"')
[ -n "${SECRET}" ] || die "获取 client secret 失败"

COORD_ENV=/etc/default/hz-coord
if [ -f "${COORD_ENV}" ]; then
  echo "==> 把 OIDC 配置写入 ${COORD_ENV} 并重启 hz-coord"
  old_args=$(grep '^HZ_COORD_ARGS=' "${COORD_ENV}" | cut -d= -f2-)
  stripped=$(printf '%s\n' "${old_args}" | sed -E 's/(^| )--oidc-[a-z-]+ [^ ]+//g')
  new_args="${stripped} --oidc-issuer ${ISSUER} --oidc-client-id hznet-coord --oidc-client-secret ${SECRET} --oidc-redirect-uri ${REDIRECT}"
  grep -v '^HZ_COORD_ARGS=' "${COORD_ENV}" > "${COORD_ENV}.tmp"
  printf 'HZ_COORD_ARGS=%s\n' "${new_args}" >> "${COORD_ENV}.tmp"
  mv "${COORD_ENV}.tmp" "${COORD_ENV}"
  chmod 0600 "${COORD_ENV}"
  sys restart hz-coord
  healthy=0
  for _ in $(seq 1 30); do
    if curl -fsS "https://coord.${DOMAIN}/healthz" >/dev/null 2>&1; then healthy=1; break; fi
    sleep 1
  done
  if [ "${healthy}" != "1" ]; then
    echo "警告：hz-coord 重启后 /healthz 未就绪，检查 journalctl -u hz-coord（常见原因：OIDC 发现文档获取失败）" >&2
  fi
else
  echo "警告：${COORD_ENV} 不存在（server-bootstrap.sh 未跑？），请手工把下列 OIDC 参数加进 hz-coord 启动参数" >&2
fi

echo ""
echo "Kanidm 初始化完成（口令与 secret 仅此一次显示，请立即保存）："
printf '{"client_id":"hznet-coord","client_secret":"%s","issuer":"%s","redirect_uri":"%s","admin_redirect_uri":"%s","admin_name":"%s","admin_password":"%s"}\n' \
  "${SECRET}" "${ISSUER}" "${REDIRECT}" "${ADMIN_REDIRECT}" "${ADMIN_NAME}" "${ADMIN_LOGIN_PW}"
