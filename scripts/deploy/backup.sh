#!/usr/bin/env bash
# Coordination Server SQLite 备份（docs/runbook.md §7）：在线快照（sqlite3
# .backup，对运行中的 hz-coord 安全）+ WAL checkpoint + 完整性校验。
# 用法：backup.sh [--db PATH] [--dest DIR] [--with-kanidm]
# 部署脚本依赖 bash；被 /bin/sh（Debian 的 dash 等）执行时在 set -o pipefail
# 前给出明确指引，而不是 "Illegal option -o pipefail"。
[ -n "${BASH_VERSION:-}" ] || { echo "本脚本需要 bash 运行：sudo bash $0 <参数>" >&2; exit 1; }
set -euo pipefail

DB="${HZ_COORD_DB:-/var/lib/hz-coord/hznet.db}"
DEST="${HZ_BACKUP_DIR:-/var/backups/hznet}"
WITH_KANIDM=0

usage() {
  cat >&2 <<'USAGE'
用法: backup.sh [--db PATH] [--dest DIR] [--with-kanidm]
说明: --with-kanidm 会把 Kanidm 最近一次在线备份（/var/backups/kanidm/）一并拷入。
USAGE
  exit 1
}
die() { echo "backup: ${1}" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --db) DB="${2:?--db 需要值}" ; shift 2 ;;
    --dest) DEST="${2:?--dest 需要值}" ; shift 2 ;;
    --with-kanidm) WITH_KANIDM=1 ; shift ;;
    -h|--help) usage ;;
    *) echo "未知参数：${1}" >&2 ; usage ;;
  esac
done

command -v sqlite3 >/dev/null 2>&1 || die "缺少 sqlite3（apt-get install sqlite3）"
[ -f "${DB}" ] || die "数据库不存在：${DB}"
[ "$(id -u)" = "0" ] || die "建议 root 运行（读取 ${DB} 与写 ${DEST} 需要权限）"

mkdir -p "${DEST}"
TS=$(date +%Y%m%d-%H%M%S)
OUT="${DEST}/hz-coord-${TS}.db"

# 先截断 WAL，快照即为主库文件的完整内容；两步对运行中的服务都安全。
sqlite3 "${DB}" 'PRAGMA wal_checkpoint(TRUNCATE);' || die "WAL checkpoint 失败"
sqlite3 "${DB}" ".backup '${OUT}'" || die "快照失败"

check=$(sqlite3 "${OUT}" 'PRAGMA integrity_check;')
[ "${check}" = "ok" ] || die "备份完整性校验失败：${check}"

size=$(du -h "${OUT}" | cut -f1)
echo "已备份 ${OUT}（${size}，integrity_check=ok）"

if [ "${WITH_KANIDM}" = "1" ]; then
  # Kanidm 在线备份文件名带时间戳（kanidm-YYYYMMDDHHMMSS），字典序即时间序。
  latest=$(find /var/backups/kanidm -maxdepth 1 -name 'kanidm-*.backup.jsonl' 2>/dev/null | sort | tail -1)
  if [ -n "${latest}" ]; then
    cp -p "${latest}" "${DEST}/"
    echo "已附带 Kanidm 备份 $(basename "${latest}")"
  else
    echo "警告：未找到 Kanidm 在线备份（检查 /etc/kanidm/server.toml 的 online_backup 与 systemctl status kanidm）" >&2
  fi
fi

echo "恢复方法：scripts/deploy/restore.sh --backup ${OUT}"
