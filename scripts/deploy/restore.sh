#!/usr/bin/env bash
# 从 backup.sh 的快照恢复 Coordination Server 数据库（docs/runbook.md §7）：
# 停 hz-coord → 校验快照 → 覆盖（旧库留存为 hznet.db.pre-restore.<时间戳>）
# → 启动并校验。
# 用法：restore.sh --backup FILE [--db PATH] [--no-systemctl]
# 部署脚本依赖 bash；被 /bin/sh（Debian 的 dash 等）执行时在 set -o pipefail
# 前给出明确指引，而不是 "Illegal option -o pipefail"。
[ -n "${BASH_VERSION:-}" ] || { echo "本脚本需要 bash 运行：sudo bash $0 <参数>" >&2; exit 1; }
set -euo pipefail

BACKUP=""
DB="${HZ_COORD_DB:-/var/lib/hz-coord/hznet.db}"
NO_SYSTEMCTL=0

usage() {
  cat >&2 <<'USAGE'
用法: restore.sh --backup <hz-coord-*.db> [--db PATH] [--no-systemctl]
USAGE
  exit 1
}
die() { echo "restore: ${1}" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --backup) BACKUP="${2:?--backup 需要值}" ; shift 2 ;;
    --db) DB="${2:?--db 需要值}" ; shift 2 ;;
    --no-systemctl) NO_SYSTEMCTL=1 ; shift ;;
    -h|--help) usage ;;
    *) echo "未知参数：${1}" >&2 ; usage ;;
  esac
done
[ -n "${BACKUP}" ] || usage
[ -f "${BACKUP}" ] || die "备份文件不存在：${BACKUP}"
command -v sqlite3 >/dev/null 2>&1 || die "缺少 sqlite3（apt-get install sqlite3）"
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

check=$(sqlite3 "${BACKUP}" 'PRAGMA integrity_check;')
[ "${check}" = "ok" ] || die "备份文件完整性校验失败：${check}"

echo "==> 停止 hz-coord"
sys stop hz-coord

TS=$(date +%Y%m%d-%H%M%S)
if [ -f "${DB}" ]; then
  cp -p "${DB}" "${DB}.pre-restore.${TS}"
  echo "    旧库留存为 ${DB}.pre-restore.${TS}"
fi
mkdir -p "$(dirname "${DB}")"
install -m 0644 "${BACKUP}" "${DB}"
# WAL/SHM 若残留会让新主库与旧 WAL 组合出脏读，一并清掉。
rm -f "${DB}-wal" "${DB}-shm"

live_check=$(sqlite3 "${DB}" 'PRAGMA integrity_check;')
[ "${live_check}" = "ok" ] || die "恢复后完整性校验失败（旧库仍在 .pre-restore 备份）"

echo "==> 启动 hz-coord"
sys start hz-coord
echo "完成：${DB} 已恢复自 ${BACKUP}（恢复时刻 ${TS}）"
