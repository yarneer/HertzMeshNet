#!/usr/bin/env bash
# 证书签发与安装（docs/runbook.md §3）：acme.sh 用 HTTP-01（走 nginx 80 端口
# webroot）签一张覆盖三个子域名的 SAN 证书，安装到
# /etc/hznet/tls/{coord,relay,auth}，续期后自动 reload nginx 并重启
# hz-relay / kanidm（两者各自终止 TLS，只在启动时读证书）。
# 前提：域名已备案、DNS A 记录已指向本机、安全组已放行 TCP 80/443。
# 用法：
#   scripts/deploy/certs.sh --domain <域名> --account-email <邮箱> [--force]
#   scripts/deploy/certs.sh --domain <域名> --self-signed   # 重生成占位证书
# 部署脚本依赖 bash；被 /bin/sh（Debian 的 dash 等）执行时在 set -o pipefail
# 前给出明确指引，而不是 "Illegal option -o pipefail"。
[ -n "${BASH_VERSION:-}" ] || { echo "本脚本需要 bash 运行：sudo bash $0 <参数>" >&2; exit 1; }
set -euo pipefail

DOMAIN=""
ACCOUNT_EMAIL=""
FORCE=0
SELF_SIGNED=0

usage() {
  cat >&2 <<'USAGE'
用法: certs.sh --domain <域名> --account-email <邮箱> [--force]
      certs.sh --domain <域名> --self-signed
USAGE
  exit 1
}
die() { echo "certs: ${1}" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:?--domain 需要值}" ; shift 2 ;;
    --account-email) ACCOUNT_EMAIL="${2:?--account-email 需要值}" ; shift 2 ;;
    --force) FORCE=1 ; shift ;;
    --self-signed) SELF_SIGNED=1 ; shift ;;
    -h|--help) usage ;;
    *) echo "未知参数：${1}" >&2 ; usage ;;
  esac
done
[ -n "${DOMAIN}" ] || usage
[ "$(id -u)" = "0" ] || die "需要 root（sudo）运行"

reload_consumers() {
  systemctl reload nginx
  systemctl restart hz-relay
  systemctl restart kanidm
}

if [ "${SELF_SIGNED}" = "1" ]; then
  echo "==> 重新生成占位自签证书（30 天，仅限测试环境）"
  tmp_cert="$(mktemp -d)"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${tmp_cert}/privkey.pem" -out "${tmp_cert}/fullchain.pem" \
    -days 30 -nodes -subj "/CN=coord.${DOMAIN}" \
    -addext "subjectAltName=DNS:coord.${DOMAIN},DNS:relay.${DOMAIN},DNS:auth.${DOMAIN}" \
    >/dev/null 2>&1 || die "生成自签证书失败"
  for sub in coord relay auth; do
    mkdir -p "/etc/hznet/tls/${sub}"
    install -m 0644 "${tmp_cert}/fullchain.pem" "/etc/hznet/tls/${sub}/fullchain.pem"
    install -m 0600 "${tmp_cert}/privkey.pem" "/etc/hznet/tls/${sub}/privkey.pem"
  done
  rm -rf "${tmp_cert}"
  reload_consumers
  echo "完成：占位证书已安装并重载服务"
  exit 0
fi

[ -n "${ACCOUNT_EMAIL}" ] || usage
command -v nginx >/dev/null 2>&1 || die "先运行 server-bootstrap.sh"
nginx -t >/dev/null 2>&1 || die "nginx 配置未通过校验"
mkdir -p /var/www/certbot

ACME_HOME="${HOME}/.acme.sh"
ACME="${ACME_HOME}/acme.sh"
if [ ! -x "${ACME}" ]; then
  echo "==> 安装 acme.sh 到 ${ACME_HOME}"
  curl -fsSL https://get.acme.sh | sh -s "email=${ACCOUNT_EMAIL}" \
    || die "acme.sh 安装失败（网络不通？可设 https_proxy 后重试）"
fi

CERT_ID="coord.${DOMAIN}"
if [ ! -d "${ACME_HOME}/${CERT_ID}" ]; then
  echo "==> 签发证书（HTTP-01，SAN 覆盖三个子域名）"
  "${ACME}" --issue --server letsencrypt -w /var/www/certbot \
    -d "coord.${DOMAIN}" -d "relay.${DOMAIN}" -d "auth.${DOMAIN}" \
    || die "签发失败：确认 DNS 已解析到本机、安全组已放行 TCP 80，且域名已完成备案"
elif [ "${FORCE}" = "1" ]; then
  echo "==> 强制续期"
  "${ACME}" --renew --force -d "${CERT_ID}" || die "续期失败"
else
  echo "==> 证书已签发过（续期由 acme.sh 的定时任务自动完成），只做安装"
fi

RELOAD_CMD="systemctl reload nginx && systemctl restart hz-relay && systemctl restart kanidm"
echo "==> 安装证书到 /etc/hznet/tls/（续期时自动执行 reload）"
"${ACME}" --install-cert -d "${CERT_ID}" \
  --fullchain-file /etc/hznet/tls/coord/fullchain.pem \
  --key-file /etc/hznet/tls/coord/privkey.pem \
  --reloadcmd "${RELOAD_CMD}" \
  || die "安装 coord 证书失败"
"${ACME}" --install-cert -d "${CERT_ID}" \
  --fullchain-file /etc/hznet/tls/relay/fullchain.pem \
  --key-file /etc/hznet/tls/relay/privkey.pem \
  --reloadcmd "${RELOAD_CMD}" \
  || die "安装 relay 证书失败"
"${ACME}" --install-cert -d "${CERT_ID}" \
  --fullchain-file /etc/hznet/tls/auth/fullchain.pem \
  --key-file /etc/hznet/tls/auth/privkey.pem \
  --reloadcmd "${RELOAD_CMD}" \
  || die "安装 auth 证书失败"

chmod 0600 /etc/hznet/tls/*/privkey.pem
echo "完成。自检："
echo "  curl -fsS https://coord.${DOMAIN}/healthz"
echo "  curl -fsS https://auth.${DOMAIN}/status"
