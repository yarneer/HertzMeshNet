#!/usr/bin/env bash
# 服务端升级（docs/runbook.md §7）：停服务 → 换 /usr/local/bin 二进制 → 刷新
# 分发目录 → 启动（sqlx 迁移在 hz-coord 启动时自动执行，见
# crates/hz-coord/src/store.rs 的 sqlx::migrate!）→ 健康检查。
# Node 升级不在本脚本范围：在各 Node 上重新执行 install.sh（runbook §7）。
# 用法：upgrade.sh --dist <新分发目录> [--no-systemctl]
set -euo pipefail

DIST=""
NO_SYSTEMCTL=0

usage() {
  cat >&2 <<'USAGE'
用法: upgrade.sh --dist <新分发目录> [--no-systemctl]
说明: 新旧版本回滚：用旧分发目录再跑一次本脚本即可（数据库迁移的回滚不支持，
      升级前务必先 backup.sh）。
USAGE
  exit 1
}
die() { echo "upgrade: ${1}" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dist) DIST="${2:?--dist 需要值}" ; shift 2 ;;
    --no-systemctl) NO_SYSTEMCTL=1 ; shift ;;
    -h|--help) usage ;;
    *) echo "未知参数：${1}" >&2 ; usage ;;
  esac
done
[ -n "${DIST}" ] || usage
DIST="$(cd "${DIST}" && pwd)" || die "分发目录不存在"
for bin_name in hz-coord hz-relay hzd hz; do
  [ -x "${DIST}/linux-x86_64/${bin_name}" ] \
    || die "分发目录缺 linux-x86_64/${bin_name}"
done
[ "$(id -u)" = "0" ] || die "需要 root（sudo）运行"

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

version_of() { "${1}" --version 2>/dev/null || echo "未知"; }

echo "==> 升级前版本：hz-coord $(version_of /usr/local/bin/hz-coord)，hz-relay $(version_of /usr/local/bin/hz-relay)"

echo "==> 停止服务（hz-relay hz-coord hzd）"
sys stop hz-relay hz-coord hzd

echo "==> 安装新二进制"
for bin_name in hz-coord hz-relay hzd hz; do
  install -m 0755 "${DIST}/linux-x86_64/${bin_name}" "/usr/local/bin/${bin_name}"
done

rm -rf /var/lib/hz-coord/dist.new
mkdir -p /var/lib/hz-coord/dist.new
cp -a "${DIST}/." /var/lib/hz-coord/dist.new/
rm -rf /var/lib/hz-coord/dist.old
if [ -d /var/lib/hz-coord/dist ]; then
  mv /var/lib/hz-coord/dist /var/lib/hz-coord/dist.old
fi
mv /var/lib/hz-coord/dist.new /var/lib/hz-coord/dist
rm -rf /var/lib/hz-coord/dist.old

echo "==> 启动 hz-coord（含数据库迁移）"
sys start hz-coord
if [ "${SYSTEMCTL}" = "1" ]; then
  healthy=0
  for _ in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1; then healthy=1; break; fi
    sleep 1
  done
  [ "${healthy}" = "1" ] || die "hz-coord 未就绪，查 journalctl -u hz-coord -n 50"
fi

echo "==> 启动 hz-relay 与 hzd"
sys start hz-relay hzd

echo "==> 升级后版本：hz-coord $(version_of /usr/local/bin/hz-coord)，hz-relay $(version_of /usr/local/bin/hz-relay)"
echo "完成。Node 侧升级在各 Node 重新执行：curl -fsSL https://coord.<域名>/install.sh | sudo sh"
