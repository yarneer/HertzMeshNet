#!/usr/bin/env bash
# HzNet 服务端一键部署（docs/runbook.md §4）：
#   二进制 + systemd 单元 + nginx 443 SNI 分流 + Kanidm 配置 + 占位证书。
# 幂等：重复执行不覆盖已生成的 /etc/default 环境文件（其中可能已回填
# OIDC secret / Relay Token），其余产物按模板重写。
# 用法：
#   scripts/deploy/server-bootstrap.sh --domain <域名> --dist <分发目录> \
#     [--kanidm-tarball <本地路径或URL>] [--skip-packages] [--no-systemctl]
# 分发目录布局：<dist>/linux-x86_64/{hz-coord,hz-relay,hzd,hz}（#17 的 musl
# 产物），Node 平台目录（linux-aarch64、darwin-arm64）会原样拷到
# /var/lib/hz-coord/dist 供 /dl 下发。
# 部署脚本依赖 bash；被 /bin/sh（Debian 的 dash 等）执行时在 set -o pipefail
# 前给出明确指引，而不是 "Illegal option -o pipefail"。
[ -n "${BASH_VERSION:-}" ] || { echo "本脚本需要 bash 运行：sudo bash $0 <参数>" >&2; exit 1; }
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DOMAIN=""
DIST=""
KANIDM_TARBALL=""
SKIP_PACKAGES=0
NO_SYSTEMCTL=0

usage() {
  cat >&2 <<'USAGE'
用法: server-bootstrap.sh --domain <域名> --dist <分发目录> [选项]
选项:
  --kanidm-tarball <路径或URL>  从 Kanidm 官方发布包安装 kanidmd/kanidm
  --skip-packages               跳过 apt 安装（容器干跑用）
  --no-systemctl                只写文件，不执行 systemctl（容器干跑用）
USAGE
  exit 1
}

die() { echo "server-bootstrap: ${1}" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:?--domain 需要值}" ; shift 2 ;;
    --dist) DIST="${2:?--dist 需要值}" ; shift 2 ;;
    --kanidm-tarball) KANIDM_TARBALL="${2:?--kanidm-tarball 需要值}" ; shift 2 ;;
    --skip-packages) SKIP_PACKAGES=1 ; shift ;;
    --no-systemctl) NO_SYSTEMCTL=1 ; shift ;;
    -h|--help) usage ;;
    *) echo "未知参数：${1}" >&2 ; usage ;;
  esac
done

[ -n "${DOMAIN}" ] && [ -n "${DIST}" ] || usage
case "${DOMAIN}" in
  *://*|*/*|*" "*|.*|*.) die "域名应为裸域名（如 example.com），收到：${DOMAIN}" ;;
esac
DIST="$(cd "${DIST}" && pwd)" || die "分发目录不存在"
[ "$(id -u)" = "0" ] || die "需要 root（sudo）运行"

for bin_name in hz-coord hz-relay hzd hz; do
  [ -x "${DIST}/linux-x86_64/${bin_name}" ] \
    || die "分发目录缺 ${DIST}/linux-x86_64/${bin_name}（期望 #17 的 musl 产物布局）"
done
[ -f "${ROOT}/packaging/deploy/nginx/hznet-stream.conf.template" ] \
  || die "缺少仓库打包文件，请在仓库内运行本脚本"

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

echo "==> 域名 ${DOMAIN}，分发目录 ${DIST}"

if [ "${SKIP_PACKAGES}" != "1" ]; then
  echo "==> 安装系统依赖（nginx + stream 模块、openssl、sqlite3、curl、python3）"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq nginx libnginx-mod-stream openssl sqlite3 curl ca-certificates python3
fi
command -v nginx >/dev/null 2>&1 || die "缺少 nginx（apt-get install nginx libnginx-mod-stream）"
command -v openssl >/dev/null 2>&1 || die "缺少 openssl"

echo "==> 安装二进制到 /usr/local/bin"
for bin_name in hz-coord hz-relay hzd hz; do
  install -m 0755 "${DIST}/linux-x86_64/${bin_name}" "/usr/local/bin/${bin_name}"
done

echo "==> 写状态与分发目录"
mkdir -p /var/lib/hz-coord /var/backups/hznet /var/backups/kanidm
rm -rf /var/lib/hz-coord/dist.new
mkdir -p /var/lib/hz-coord/dist.new
cp -a "${DIST}/." /var/lib/hz-coord/dist.new/
rm -rf /var/lib/hz-coord/dist.old
if [ -d /var/lib/hz-coord/dist ]; then
  mv /var/lib/hz-coord/dist /var/lib/hz-coord/dist.old
fi
mv /var/lib/hz-coord/dist.new /var/lib/hz-coord/dist
rm -rf /var/lib/hz-coord/dist.old

echo "==> 写 /etc/default 环境文件（存在则保留，避免覆盖已回填的 secret）"
write_env() {
  local target="$1" template="$2"
  if [ -f "${target}" ]; then
    echo "    ${target} 已存在，保留不动（如需重建请先备份并删除）"
  else
    sed "s/@DOMAIN@/${DOMAIN}/g" "${template}" > "${target}"
    chmod 0644 "${target}"
    echo "    已生成 ${target}"
  fi
}
write_env /etc/default/hz-coord "${ROOT}/packaging/deploy/env/hz-coord.env.template"
write_env /etc/default/hz-relay "${ROOT}/packaging/deploy/env/hz-relay.env.template"
write_env /etc/default/hzd "${ROOT}/packaging/deploy/env/hzd.env.template"

echo "==> 安装 systemd 单元"
install -m 0644 "${ROOT}/packaging/systemd/hz-coord.service" /etc/systemd/system/hz-coord.service
install -m 0644 "${ROOT}/packaging/systemd/hz-relay.service" /etc/systemd/system/hz-relay.service
install -m 0644 "${ROOT}/packaging/systemd/hzd.service" /etc/systemd/system/hzd.service
install -m 0644 "${ROOT}/packaging/deploy/kanidm/kanidm.service" /etc/systemd/system/kanidm.service
sys daemon-reload

if [ -n "${KANIDM_TARBALL}" ]; then
  echo "==> 安装 Kanidm 二进制"
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir}"' EXIT
  case "${KANIDM_TARBALL}" in
    http://*|https://*)
      curl -fSL -o "${tmp_dir}/kanidm.tar.gz" "${KANIDM_TARBALL}" \
        || die "下载 Kanidm 发布包失败：${KANIDM_TARBALL}"
      tar -xzf "${tmp_dir}/kanidm.tar.gz" -C "${tmp_dir}" \
        || die "解压 Kanidm 发布包失败"
      ;;
    *)
      tar -xzf "${KANIDM_TARBALL}" -C "${tmp_dir}" || die "解压 Kanidm 发布包失败"
      ;;
  esac
  found=0
  while IFS= read -r bin_path; do
    install -m 0755 "${bin_path}" "/usr/local/bin/$(basename "${bin_path}")"
    echo "    已安装 $(basename "${bin_path}")"
    found=1
  done < <(find "${tmp_dir}" -type f \( -name kanidmd -o -name kanidm \))
  [ "${found}" = "1" ] || die "发布包里没找到 kanidmd/kanidm 二进制"
fi

echo "==> 写 Kanidm 配置 /etc/kanidm/server.toml"
mkdir -p /etc/kanidm
sed "s/@DOMAIN@/${DOMAIN}/g" \
  "${ROOT}/packaging/deploy/kanidm/server.toml.template" > /etc/kanidm/server.toml

echo "==> 配置 nginx（443 SNI 分流 + coord TLS 终止 + 80 ACME）"
mkdir -p /etc/nginx/streams-enabled /var/www/certbot
if ! grep -q 'streams-enabled' /etc/nginx/nginx.conf; then
  printf '\nstream {\n    include /etc/nginx/streams-enabled/*.conf;\n}\n' \
    >> /etc/nginx/nginx.conf
  echo "    已在 nginx.conf 追加 stream{} include"
fi
sed "s/@DOMAIN@/${DOMAIN}/g" \
  "${ROOT}/packaging/deploy/nginx/hznet-stream.conf.template" \
  > /etc/nginx/streams-enabled/hznet.conf
sed "s/@DOMAIN@/${DOMAIN}/g" \
  "${ROOT}/packaging/deploy/nginx/hznet-http.conf.template" \
  > /etc/nginx/sites-available/hznet
ln -sfn /etc/nginx/sites-available/hznet /etc/nginx/sites-enabled/hznet
rm -f /etc/nginx/sites-enabled/default

echo "==> 证书目录与占位自签证书（正式证书由 certs.sh 换发）"
# 每个子域名一张证书、SAN 只含自身：三个子域名同 IP，多 SAN 证书会让浏览器
# 复用 coord 的连接去请求 auth，被 443 的 SNI 分流送错后端（runbook §3）。
placeholder_made=0
for sub in coord relay auth; do
  mkdir -p "/etc/hznet/tls/${sub}"
  [ -f "/etc/hznet/tls/${sub}/fullchain.pem" ] && continue
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "/etc/hznet/tls/${sub}/privkey.pem" -out "/etc/hznet/tls/${sub}/fullchain.pem" \
    -days 30 -nodes -subj "/CN=${sub}.${DOMAIN}" \
    -addext "subjectAltName=DNS:${sub}.${DOMAIN}" \
    >/dev/null 2>&1 || die "生成 ${sub} 占位证书失败"
  chmod 0644 "/etc/hznet/tls/${sub}/fullchain.pem"
  chmod 0600 "/etc/hznet/tls/${sub}/privkey.pem"
  placeholder_made=1
done
if [ "${placeholder_made}" = "1" ]; then
  echo "    已生成 30 天占位证书（浏览器/客户端会告警，仅用于先把服务拉起）"
fi

nginx -t || die "nginx 配置校验未通过"

echo "==> 启动服务"
sys enable --now nginx
if [ -x /usr/local/bin/kanidmd ]; then
  sys enable --now kanidm
else
  echo "    [提示] 未安装 kanidmd：加 --kanidm-tarball 或按 runbook §5 手动安装后 systemctl enable --now kanidm"
fi
sys enable --now hz-coord hz-relay hzd

echo ""
echo "部署完成。下一步（runbook §4）："
echo "  1. scripts/deploy/certs.sh --domain ${DOMAIN} --account-email <邮箱>   # 换正式证书"
echo "  2. scripts/deploy/kanidm-init.sh --domain ${DOMAIN} --admin-name <名字> # OIDC + 首个 Admin"
echo "  3. scripts/deploy/hz-bootstrap.sh --admin <名字>                       # 第一把 Auth Key + Relay Token"
