#!/usr/bin/env bash
# 部署侧只读健康检查（docs/runbook.md §7.6）。不重启、不改文件。
# 检查 Coordination Server 的 /healthz、Relay TLS、Kanidm /status、
# nginx -t（有 nginx 才查）、三个子域名证书到期、三条 DNS A 记录
# （有 getent 或 python3 才查）。任一项 FAIL 则退出码非零。
# 每行 PASS/FAIL/SKIP 开头，供以后 Admin Console 健康页复用。
# 用法：healthcheck.sh [--domain <域名>] [--cert-days 14]
# 部署脚本依赖 bash；被 /bin/sh（Debian 的 dash 等）执行时在 set -o pipefail
# 前给出明确指引，而不是 "Illegal option -o pipefail"。
[ -n "${BASH_VERSION:-}" ] || { echo "本脚本需要 bash 运行：sudo bash $0 <参数>" >&2; exit 1; }
set -euo pipefail

PASS=0
FAIL=0
SKIPS=0
DOMAIN=""
CERT_DAYS=14

pass() { echo "PASS $*"; PASS=$((PASS + 1)); }
fail() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP $*"; SKIPS=$((SKIPS + 1)); }
die() { echo "healthcheck: ${1}" >&2; exit 1; }

usage() {
  cat >&2 <<'USAGE'
用法: healthcheck.sh [--domain <域名>] [--cert-days 14]
说明: 只读。省略 --domain 时从 /etc/default/hz-coord 的 --public-url
      （其次 /etc/default/hzd 的 HZD_COORD_ADDR）推导，主机名须为 coord.<域名>。
      --cert-days 内将到期的证书算 FAIL（默认 14）。
USAGE
  exit 1
}

# https://coord.example.com[:port][/path] → example.com。不是这个形态则失败。
domain_from_coord_url() {
  local url="$1" rest host
  case "$url" in
    http://*|https://*) ;;
    *) return 1 ;;
  esac
  rest=${url#*://}
  rest=${rest%%/*}
  host=${rest%%:*}
  case "$host" in
    coord.*.*)
      printf '%s\n' "${host#coord.}"
      ;;
    *) return 1 ;;
  esac
}

public_url_from_hz_coord_file() {
  sed -n 's/.*--public-url[[:space:]][[:space:]]*\([^[:space:]]*\).*/\1/p' "$1" | head -n 1
}

domain_from_installed() {
  local url=""
  if [ -f /etc/default/hz-coord ]; then
    url=$(public_url_from_hz_coord_file /etc/default/hz-coord || true)
  fi
  if [ -z "$url" ] && [ -f /etc/default/hzd ]; then
    url=$(sed -n 's/^[[:space:]]*HZD_COORD_ADDR=//p' /etc/default/hzd | head -n 1 || true)
    url=${url#\"}
    url=${url%\"}
  fi
  [ -n "$url" ] || return 1
  domain_from_coord_url "$url"
}

# 0：notAfter 仍晚于现在 + days。openssl 缺失或文件坏也是非 0。
cert_healthy() {
  openssl x509 -checkend "$(( $2 * 86400 ))" -noout -in "$1" >/dev/null 2>&1
}

cert_self_signed() {
  local subject issuer
  subject=$(openssl x509 -in "$1" -noout -subject | sed 's/^subject= *//')
  issuer=$(openssl x509 -in "$1" -noout -issuer | sed 's/^issuer= *//')
  [ "$subject" = "$issuer" ]
}

cert_not_after() {
  openssl x509 -in "$1" -noout -enddate -dateopt iso_8601 2>/dev/null \
    || openssl x509 -in "$1" -noout -enddate
}

lookup_a() {
  local name="$1" ip
  if command -v getent >/dev/null 2>&1; then
    ip=$(getent ahostsv4 "$name" 2>/dev/null | awk 'NR==1 {print $1}' || true)
    if [ -n "$ip" ]; then
      printf '%s\n' "$ip"
      return 0
    fi
    return 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import socket,sys
try:
    infos=socket.getaddrinfo(sys.argv[1], None, socket.AF_INET)
except OSError:
    sys.exit(1)
print(infos[0][4][0])' "$name"
    return
  fi
  return 2
}

tls_ok() {
  if command -v timeout >/dev/null 2>&1; then
    timeout 8 openssl s_client -connect "$1:$2" -servername "$3" </dev/null >/dev/null 2>&1
  else
    openssl s_client -connect "$1:$2" -servername "$3" </dev/null >/dev/null 2>&1
  fi
}

one_line() { tr '\n' ' ' | sed 's/[[:space:]]*$//' | cut -c1-180; }

check_coord() {
  local errf body trimmed why
  errf=$(mktemp)
  if body=$(curl -fsS --max-time 5 http://127.0.0.1:8080/healthz 2>"$errf"); then
    trimmed=$(printf '%s' "$body" | tr -d '[:space:]')
    if [ "$trimmed" = "ok" ]; then
      pass "coord http://127.0.0.1:8080/healthz"
    else
      fail "coord /healthz 期望 ok，得到 ${trimmed:-<空>}"
    fi
  else
    why=$(one_line <"$errf" || true)
    fail "coord http://127.0.0.1:8080/healthz 不可达${why:+: ${why}}"
  fi
  rm -f "$errf"
}

check_relay() {
  local name="relay.${DOMAIN}"
  if tls_ok 127.0.0.1 443 "$name"; then
    pass "relay ${name}:443"
    return
  fi
  if tls_ok 127.0.0.1 8444 "$name"; then
    fail "relay ${name}:443 握手失败（127.0.0.1:8444 通，检查 nginx stream）"
    return
  fi
  fail "relay ${name} 不可达（127.0.0.1:443 与 :8444）"
}

check_kanidm() {
  local name="auth.${DOMAIN}"
  local url="https://${name}/status" errf body trimmed why cert
  local -a args
  errf=$(mktemp)
  args=(-fsS --max-time 8 --resolve "${name}:443:127.0.0.1")
  cert="/etc/hznet/tls/auth/fullchain.pem"
  # 占位自签证书不在系统信任库里；用装好的那张校验，正式证书仍走系统 CA。
  if [ -f "$cert" ] && cert_self_signed "$cert"; then
    args+=(--cacert "$cert")
  fi
  if body=$(curl "${args[@]}" "$url" 2>"$errf"); then
    trimmed=$(printf '%s' "$body" | tr -d '[:space:]')
    if [ "$trimmed" = "true" ]; then
      pass "kanidm ${url}"
    else
      fail "kanidm ${url} 期望 true，得到 ${trimmed:-<空>}"
    fi
  else
    why=$(one_line <"$errf" || true)
    fail "kanidm ${url} 不可达${why:+: ${why}}"
  fi
  rm -f "$errf"
}

check_nginx() {
  local err
  if ! command -v nginx >/dev/null 2>&1; then
    skip "nginx -t（未安装 nginx）"
    return
  fi
  if err=$(nginx -t 2>&1); then
    pass "nginx -t"
  else
    err=$(printf '%s' "$err" | one_line)
    fail "nginx -t: ${err}"
  fi
}

check_certs() {
  local sub file end
  for sub in coord relay auth; do
    file="/etc/hznet/tls/${sub}/fullchain.pem"
    if [ ! -f "$file" ]; then
      fail "cert ${sub} 缺少 ${file}"
      continue
    fi
    end=$(cert_not_after "$file")
    end=${end#notAfter=}
    if cert_healthy "$file" "$CERT_DAYS"; then
      pass "cert ${sub} notAfter=${end}"
    else
      fail "cert ${sub} 将在 ${CERT_DAYS} 天内到期或已过期（notAfter=${end}）"
    fi
  done
}

check_dns() {
  local sub name ip c_ip="" r_ip="" a_ip=""
  if ! command -v getent >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
    skip "dns A 记录（无 getent 或 python3）"
    return
  fi
  for sub in coord relay auth; do
    name="${sub}.${DOMAIN}"
    if ip=$(lookup_a "$name"); then
      pass "dns ${name} A ${ip}"
      case "$sub" in
        coord) c_ip=$ip ;;
        relay) r_ip=$ip ;;
        auth) a_ip=$ip ;;
      esac
    else
      fail "dns ${name} 无 A 记录"
    fi
  done
  if [ -n "$c_ip" ] && [ -n "$r_ip" ] && [ -n "$a_ip" ] && { [ "$c_ip" != "$r_ip" ] || [ "$c_ip" != "$a_ip" ]; }; then
    fail "dns 三条 A 记录不一致：coord=${c_ip} relay=${r_ip} auth=${a_ip}"
  fi
}

self_check() {
  local tmp url got
  got=$(domain_from_coord_url "https://coord.example.com")
  [ "$got" = "example.com" ] || die "domain 主机名：[$got]"
  got=$(domain_from_coord_url "https://coord.example.com:443/healthz")
  [ "$got" = "example.com" ] || die "domain 端口与路径：[$got]"
  if domain_from_coord_url "http://coord:8080" >/dev/null 2>&1; then
    die "裸主机名不应推出域名"
  fi
  tmp=$(mktemp -d)
  trap 'rm -rf '"$tmp" EXIT
  printf '%s\n' 'HZ_COORD_ARGS=--public-url https://coord.example.com --public-grpc-addr https://coord.example.com' > "$tmp/hz-coord"
  url=$(public_url_from_hz_coord_file "$tmp/hz-coord")
  [ "$url" = "https://coord.example.com" ] || die "public-url 解析：[$url]"
  command -v openssl >/dev/null 2>&1 || die "self-check 需要 openssl"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$tmp/long.key" -out "$tmp/long.pem" -days 365 -nodes \
    -subj "/CN=coord.example.com" >/dev/null 2>&1
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$tmp/short.key" -out "$tmp/short.pem" -days 1 -nodes \
    -subj "/CN=coord.example.com" >/dev/null 2>&1
  cert_healthy "$tmp/long.pem" 14 || die "365 天证书不应在 14 天窗口内失败"
  if cert_healthy "$tmp/short.pem" 14; then
    die "1 天证书应算作即将到期"
  fi
  cert_self_signed "$tmp/long.pem" || die "openssl req 自签证书应判定为自签"
  echo "self-check: PASS"
}

if [ "${1:-}" = "--self-check" ]; then
  self_check
  exit 0
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:?--domain 需要值}" ; shift 2 ;;
    --cert-days) CERT_DAYS="${2:?--cert-days 需要值}" ; shift 2 ;;
    -h|--help) usage ;;
    *) echo "未知参数：${1}" >&2 ; usage ;;
  esac
done

case "$CERT_DAYS" in
  ''|*[!0-9]*) die "--cert-days 需要非负整数" ;;
esac

if [ -z "$DOMAIN" ]; then
  DOMAIN=$(domain_from_installed) || die "请传 --domain <域名>，或先完成 server-bootstrap.sh（从 --public-url / HZD_COORD_ADDR 推导）"
fi
case "$DOMAIN" in
  *://*|*/*|*" "*|.*|*.) die "域名应为裸域名（如 example.com），收到：${DOMAIN}" ;;
esac

[ "$(id -u)" = "0" ] || die "需要 root（sudo）运行"
command -v curl >/dev/null 2>&1 || die "缺少 curl"
command -v openssl >/dev/null 2>&1 || die "缺少 openssl"

check_coord
check_relay
check_kanidm
check_nginx
check_certs
check_dns

echo "healthcheck: ${PASS} PASS, ${FAIL} FAIL, ${SKIPS} SKIP"
[ "$FAIL" -eq 0 ]
