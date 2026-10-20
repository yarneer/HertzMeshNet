#!/usr/bin/env bash
# 证书签发与安装（docs/runbook.md §3）：acme.sh 用 HTTP-01（走 nginx 80 端口
# webroot）为 coord / relay / auth 三个子域名各签一张只含自身名字的证书，分别
# 安装到 /etc/hznet/tls/{coord,relay,auth}，续期后各自重载使用者（nginx reload、
# 重启 hz-relay、重启 kanidm；后两者自行终止 TLS，只在启动时读证书）。
# 不用一张多 SAN 证书：三个子域名同 IP，浏览器会凭多 SAN 证书复用 coord 的连接
# 去请求 auth，而 443 按 SNI 整条连接分流，请求被送错后端。
# 已按旧方式（一张证书三个 SAN）安装的环境，再次运行本脚本即换发为单域名证书。
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
NO_SYSTEMCTL=0

usage() {
  cat >&2 <<'USAGE'
用法: certs.sh --domain <域名> --account-email <邮箱> [--force] [--no-systemctl]
      certs.sh --domain <域名> --self-signed [--no-systemctl]
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
    --no-systemctl) NO_SYSTEMCTL=1 ; shift ;;
    -h|--help) usage ;;
    *) echo "未知参数：${1}" >&2 ; usage ;;
  esac
done
[ -n "${DOMAIN}" ] || usage
[ "$(id -u)" = "0" ] || die "需要 root（sudo）运行"

SUBS=(coord relay auth)

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

# 各子域名证书的使用者与重载方式。
reload_cmd_for() {
  case "$1" in
    coord) echo "systemctl reload nginx" ;;
    relay) echo "systemctl restart hz-relay" ;;
    auth) echo "systemctl restart kanidm" ;;
  esac
}
reload_one() {
  case "$1" in
    coord) sys reload nginx ;;
    relay) sys restart hz-relay ;;
    auth) sys restart kanidm ;;
  esac
}

# 证书里除自身名字外还有别的 DNS 名（旧版一张证书三个 SAN）时为真。
has_foreign_san() {
  local file="$1" name="$2"
  [ -f "${file}" ] || return 1
  openssl x509 -in "${file}" -noout -text 2>/dev/null \
    | grep -o 'DNS:[^,[:space:]]*' | grep -qvx "DNS:${name}"
}

if [ "${SELF_SIGNED}" = "1" ]; then
  echo "==> 重新生成占位自签证书（每个子域名一张，30 天，仅限测试环境）"
  for sub in "${SUBS[@]}"; do
    name="${sub}.${DOMAIN}"
    dir="/etc/hznet/tls/${sub}"
    tmp_cert="$(mktemp -d)"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout "${tmp_cert}/privkey.pem" -out "${tmp_cert}/fullchain.pem" \
      -days 30 -nodes -subj "/CN=${name}" \
      -addext "subjectAltName=DNS:${name}" \
      >/dev/null 2>&1 || die "生成 ${name} 自签证书失败"
    mkdir -p "${dir}"
    install -m 0644 "${tmp_cert}/fullchain.pem" "${dir}/fullchain.pem"
    install -m 0600 "${tmp_cert}/privkey.pem" "${dir}/privkey.pem"
    rm -rf "${tmp_cert}"
  done
  for sub in "${SUBS[@]}"; do
    reload_one "${sub}"
  done
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

# acme.sh 已管理的证书（--list 首列为主域名）。
acme_has_cert() {
  "${ACME}" --list 2>/dev/null | awk 'NR > 1 { print $1 }' | grep -qx "$1"
}

for sub in "${SUBS[@]}"; do
  name="${sub}.${DOMAIN}"
  dir="/etc/hznet/tls/${sub}"
  mkdir -p "${dir}"
  if has_foreign_san "${dir}/fullchain.pem" "${name}"; then
    # 旧版的 coord.<域名> 证书带 relay/auth 两个 SAN：按单域名强制重签。
    echo "==> ${name}：已安装的证书含其他子域名，换发为单域名证书"
    "${ACME}" --issue --force --server letsencrypt -w /var/www/certbot -d "${name}" \
      || die "${name} 签发失败：确认 DNS 已解析到本机、安全组已放行 TCP 80，且域名已完成备案"
  elif ! acme_has_cert "${name}"; then
    echo "==> ${name}：签发证书（HTTP-01）"
    "${ACME}" --issue --server letsencrypt -w /var/www/certbot -d "${name}" \
      || die "${name} 签发失败：确认 DNS 已解析到本机、安全组已放行 TCP 80，且域名已完成备案"
  elif [ "${FORCE}" = "1" ]; then
    echo "==> ${name}：强制续期"
    "${ACME}" --renew --force -d "${name}" || die "${name} 续期失败"
  else
    echo "==> ${name}：证书已签发过（续期由 acme.sh 的定时任务自动完成），只做安装"
  fi

  echo "==> ${name}：安装到 ${dir}（续期时自动执行：$(reload_cmd_for "${sub}")）"
  "${ACME}" --install-cert -d "${name}" \
    --fullchain-file "${dir}/fullchain.pem" \
    --key-file "${dir}/privkey.pem" \
    --reloadcmd "$(reload_cmd_for "${sub}")" \
    || die "安装 ${name} 证书失败"
  chmod 0600 "${dir}/privkey.pem"
done

echo "完成。自检："
echo "  curl -fsS https://coord.${DOMAIN}/healthz"
echo "  curl -fsS https://auth.${DOMAIN}/status"
