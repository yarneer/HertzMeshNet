#!/usr/bin/env bash
# 首次引导（docs/runbook.md §6）：种第一个 Admin、签第一把 Auth Key；若
# /etc/default/hz-relay 仍是 Relay Token 占位符，则顺带签发 Relay Token 回填
# 并重启 hz-relay。Auth Key 与 Relay Token 都只在签发时显示一次。
# 用法：hz-bootstrap.sh [--admin <名字>] [--expiry 90d] [--once] [--no-systemctl]
# 部署脚本依赖 bash；被 /bin/sh（Debian 的 dash 等）执行时在 set -o pipefail
# 前给出明确指引，而不是 "Illegal option -o pipefail"。
[ -n "${BASH_VERSION:-}" ] || { echo "本脚本需要 bash 运行：sudo bash $0 <参数>" >&2; exit 1; }
set -euo pipefail

ADMIN=""
EXPIRY="90d"
ONCE=0
NO_SYSTEMCTL=0

usage() {
  cat >&2 <<'USAGE'
用法: hz-bootstrap.sh [--admin <名字>] [--expiry 90d] [--once] [--no-systemctl]
说明: --admin 与 kanidm-init.sh 的 --admin-name 一致时，该 User 名下 Node 可远程管理；
      重复执行会签发新的 Auth Key（旧 Key 不受影响）；Relay Token 已回填过则不再重签。
USAGE
  exit 1
}
die() { echo "hz-bootstrap: ${1}" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --admin) ADMIN="${2:?--admin 需要值}" ; shift 2 ;;
    --expiry) EXPIRY="${2:?--expiry 需要值}" ; shift 2 ;;
    --once) ONCE=1 ; shift ;;
    --no-systemctl) NO_SYSTEMCTL=1 ; shift ;;
    -h|--help) usage ;;
    *) echo "未知参数：${1}" >&2 ; usage ;;
  esac
done

[ "$(id -u)" = "0" ] || die "需要 root（sudo）运行"
DB="${HZ_COORD_DB:-/var/lib/hz-coord/hznet.db}"
COORD_BIN="${HZ_COORD_BIN:-/usr/local/bin/hz-coord}"
RELAY_ENV=/etc/default/hz-relay
COORD_ENV=/etc/default/hz-coord
[ -x "${COORD_BIN}" ] || die "缺少 ${COORD_BIN}（先运行 server-bootstrap.sh）"

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

if [ -f "${COORD_ENV}" ] && ! grep -q -- '--oidc-issuer' "${COORD_ENV}"; then
  echo "警告：${COORD_ENV} 尚未启用 OIDC（先运行 kanidm-init.sh，否则交互式登录不可用）" >&2
fi

NEED_TOKEN=0
if [ -f "${RELAY_ENV}" ] && grep -q '@RELAY_TOKEN@' "${RELAY_ENV}"; then
  NEED_TOKEN=1
fi

args=(--db "${DB}" --auth-key-expiry "${EXPIRY}" --json)
[ -n "${ADMIN}" ] && args+=(--admin "${ADMIN}")
[ "${ONCE}" = "1" ] && args+=(--once)
[ "${NEED_TOKEN}" = "1" ] && args+=(--relay-token)

echo "==> 签发 Auth Key（数据库 ${DB}）"
raw=$("${COORD_BIN}" bootstrap "${args[@]}") || die "hz-coord bootstrap 失败"
auth_key=$(printf '%s' "${raw}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["auth_key"])')
expires_at=$(printf '%s' "${raw}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["expires_at_unix"])')
relay_token=""
if [ "${NEED_TOKEN}" = "1" ]; then
  relay_token=$(printf '%s' "${raw}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("relay_token",""))')
  [ -n "${relay_token}" ] || die "输出里没有 relay_token"
  echo "==> 回填 Relay Token 到 ${RELAY_ENV} 并重启 hz-relay"
  sed "s/@RELAY_TOKEN@/${relay_token}/" "${RELAY_ENV}" > "${RELAY_ENV}.tmp"
  mv "${RELAY_ENV}.tmp" "${RELAY_ENV}"
  chmod 0600 "${RELAY_ENV}"
  sys restart hz-relay
else
  echo "==> Relay Token 已存在，不再重签"
fi

expires_human=$(python3 -c "import datetime; print(datetime.datetime.fromtimestamp(${expires_at}, datetime.timezone.utc).isoformat())")
echo ""
echo "引导完成。以下凭据仅此一次显示，请立即保存："
printf 'Auth Key（%s 前有效）：%s\n' "${expires_human}" "${auth_key}"
if [ -n "${ADMIN}" ]; then
  printf '已落库为 Admin 的 User：%s\n' "${ADMIN}"
fi
if [ -n "${relay_token}" ]; then
  printf 'Relay Token（已写入 %s）：%s\n' "${RELAY_ENV}" "${relay_token}"
fi
echo "首个 Node 接入（runbook §6）：在目标机执行"
echo "  curl -fsSL https://coord.<域名>/install.sh | sudo sh"
