#!/usr/bin/env bash
# 把一个空白的 Kanidm 配置成 #10 集成测试要用的样子：
#   persons: alice（hznet_admins 成员）、bob（普通 User）、hznet_setup（OAuth2 管理员）
#   oauth2 client: hznet-coord（机密客户端 + PKCE，回调注册为参数传入的两个端口，
#   以及各自的 /admin/oidc/callback）
# 输出：一行 JSON（client_id/client_secret/issuer/alice/bob 密码）供 run.sh 注入测试。
#
# 依据实测（kanidm 1.8.0）：
#   - person 的口令只能走 credential-update 会话 API（CLI 无非交互 set-password）；
#   - system oauth2 写操作需要特权会话：password 登录得到 PrivilegeCapable token，
#     再 POST /v1/reauth + 带会话头的 /v1/auth 完成口令升级，全程 curl 可驱动。
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_PORT="${KANIDM_HOST_PORT:-18443}"
ISSUER="https://localhost:${HOST_PORT}"
REDIRECT_1="${KANIDM_REDIRECT_1:?需要 coord 回调地址（正常 TTL 实例）}"
REDIRECT_2="${KANIDM_REDIRECT_2:?需要 coord 回调地址（短 TTL 实例）}"
# 口令避开账号名/姓氏词，否则 Kanidm 的口令质量检查会拒绝提交。
ALICE_PW="Quasar-Lantern-4821"
BOB_PW="Nebula-Carriage-7364"
SETUP_PW="Zephyr-Harmonic-5509"

compose() { docker compose -f "$DIR/docker-compose.yml" "$@"; }
# CLI 的 token 落在 $HOME/.cache/kanidm_tokens；每个身份一个 HOME，避免
# 多 token 时 CLI 交互式询问"用哪个"（无 TTY 会直接失败）。
kanidm() {
  local cache="$1"; shift
  compose exec -T -e "HOME=/cache/$cache" -e "KANIDM_CACHE_DIR=/cache/$cache" tools kanidm "$@"
}

note() { printf '[kanidm-setup] %s\n' "$*"; }

wait_ready() {
  for _ in $(seq 1 60); do
    if curl -sk "$ISSUER/status" | grep -q true; then return 0; fi
    sleep 1
  done
  echo "Kanidm 未就绪" >&2
  return 1
}

# 经 credential-update 会话 API 设口令（CLI 的重置令牌 + curl 三步）。
# 质量检查不通过时 update 会返回 passwordquality 警告且不可提交，这里显式失败。
set_password() {
  local user="$1" password="$2"
  local token sess update commit
  token=$(kanidm idm person credential create-reset-token "$user" 2>/dev/null \
    | grep 'use-reset-token' | awk '{print $NF}')
  sess=$(curl -sk -X POST "$ISSUER/v1/credential/_exchange_intent" \
    -H 'Content-Type: application/json' -d "\"$token\"" \
    | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)[0]))')
  update=$(curl -sk -X POST "$ISSUER/v1/credential/_update" -H 'Content-Type: application/json' \
    -d "[{\"password\":\"$password\"},$sess]")
  echo "$update" | grep -q '"can_commit":true' \
    || { echo "口令被质量检查拒绝（${user}）：$update" >&2; exit 1; }
  commit=$(curl -sk -X POST "$ISSUER/v1/credential/_commit" -H 'Content-Type: application/json' \
    -d "$sess")
  [ "$commit" = "null" ] || { echo "口令提交失败（${user}）：$commit" >&2; exit 1; }
}

# 口令登录 → 特权升级 → 输出特权 bearer。认证会话靠 auth-session-id cookie
# 接力（与官方客户端一致）；失败时整段报错退出。
privileged_token() {
  local user="$1" password="$2"
  python3 - "$ISSUER" "$user" "$password" <<'PYEOF'
import json, subprocess, sys, tempfile, os

issuer, user, password = sys.argv[1], sys.argv[2], sys.argv[3]
jar = tempfile.NamedTemporaryFile(delete=False)
jar.close()

def post(path, body, bearer=None):
    args = ['curl', '-sk', '-b', jar.name, '-c', jar.name, '-X', 'POST',
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
  if [ -n "$body" ]; then
    curl -sk -X "$method" "$ISSUER$path" -H "Authorization: Bearer $token" \
      -H 'Content-Type: application/json' -d "$body" -w '\n%{http_code}'
  else
    curl -sk -X "$method" "$ISSUER$path" -H "Authorization: Bearer $token" \
      -w '\n%{http_code}'
  fi
}

wait_ready

note "恢复内置管理员口令并登录"
ADMIN_PW=$(compose exec -T kanidm kanidmd recover-account admin 2>/dev/null \
  | grep -o 'new_password: "[^"]*"' | cut -d'"' -f2)
IDM_PW=$(compose exec -T kanidm kanidmd recover-account idm_admin 2>/dev/null \
  | grep -o 'new_password: "[^"]*"' | cut -d'"' -f2)
[ -n "$ADMIN_PW" ] && [ -n "$IDM_PW" ] || { echo "recover-account 失败" >&2; exit 1; }
compose exec -T tools sh -c "mkdir -p /cache/admin /cache/idm" >/dev/null
kanidm admin login --name admin --password "$ADMIN_PW" >/dev/null
kanidm idm login --name idm_admin --password "$IDM_PW" >/dev/null

note "创建 persons 与组"
kanidm idm person create alice "Alice Admin" >/dev/null
kanidm idm person create bob "Bob Normal" >/dev/null
kanidm idm person create hznet_setup "OAuth2 Setup" >/dev/null
kanidm idm group create hznet_admins >/dev/null
kanidm idm group create hznet_users >/dev/null
kanidm idm group add-members hznet_admins alice >/dev/null
kanidm idm group add-members hznet_users alice bob >/dev/null
# 单因子口令要能提交：内置策略放宽到 any（测试实例）。
kanidm idm group account-policy credential-type-minimum idm_all_persons any >/dev/null
# OAuth2 客户端管理权交给专用 setup 用户（password 登录可走 curl 特权升级）。
kanidm idm group add-members idm_oauth2_admins hznet_setup >/dev/null

note "设置口令"
set_password alice "$ALICE_PW"
set_password bob "$BOB_PW"
set_password hznet_setup "$SETUP_PW"

note "创建 OAuth2 客户端（机密 + PKCE + Node 登录与 Admin Console 回调）"
PRIV=$(privileged_token hznet_setup "$SETUP_PW")
[ -n "$PRIV" ] || exit 1
out=$(api POST /v1/oauth2/_basic "$PRIV" '{"attrs":{"name":["hznet-coord"],"displayname":["HzNet Coordination Server"],"oauth2_rs_origin_landing":["http://127.0.0.1/"],"oauth2_strict_redirect_uri":["true"]}}')
echo "$out" | tail -1 | grep -q '^2' || { echo "oauth2 create 失败：$out" >&2; exit 1; }
# 回调地址走 PATCH（实测 _attr 追加端点对机密客户端返回 nomatchingentries）。
# Admin 回调与 crates/hz-coord/src/admin_http.rs 的 admin_redirect_uri 一致。
ADMIN_1="${REDIRECT_1%/oidc/callback}/admin/oidc/callback"
ADMIN_2="${REDIRECT_2%/oidc/callback}/admin/oidc/callback"
out=$(api PATCH /v1/oauth2/hznet-coord "$PRIV" \
  "{\"attrs\":{\"oauth2_rs_origin\":[\"$REDIRECT_1\",\"$REDIRECT_2\",\"$ADMIN_1\",\"$ADMIN_2\"]}}")
echo "$out" | tail -1 | grep -q '^2' || { echo "注册回调失败：$out" >&2; exit 1; }
api POST /v1/oauth2/hznet-coord/_scopemap/hznet_users "$PRIV" '["openid","profile","groups"]' >/dev/null
out=$(api PATCH /v1/oauth2/hznet-coord "$PRIV" '{"attrs":{"oauth2_prefer_short_username":["true"]}}')
echo "$out" | tail -1 | grep -q '^2' || { echo "设置短用户名偏好失败：$out" >&2; exit 1; }

SECRET=$(api GET /v1/oauth2/hznet-coord/_basic_secret "$PRIV" | head -1 | tr -d '"')

# OIDC issuer 是 Kanidm 的每客户端命名空间（发现文档挂在其下）。
printf '{"client_id":"hznet-coord","client_secret":"%s","issuer":"%s/oauth2/openid/hznet-coord","alice_password":"%s","bob_password":"%s"}\n' \
  "$SECRET" "$ISSUER" "$ALICE_PW" "$BOB_PW"
