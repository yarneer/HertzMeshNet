#!/usr/bin/env bash
# FR-13 验收：全新 debian:bookworm 容器执行一条安装命令，hzd/hz 落盘、
# systemd 单元与 /etc/default/hzd 就位，手动按单元 ExecStart 拉起 hzd 后
# `hz up --auth-key` 加入 HzNet；再验幂等重装（保留已有变量）与 sha256 防篡改负路径。
# 用法：install_docker.sh <dist_dir>，其中 <dist_dir>/<平台>/{hzd,hz,hz-coord}
# 是 musl 构建产物（平台按 Docker VM 架构自动选择）。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DIST_DIR="${1:-$ROOT/dist}"

PREFIX=hz-t17-install
NET=$PREFIX-net
COORD=$PREFIX-coord
NODE=$PREFIX-node
GRPC_PORT=9443
HTTP_PORT=8080
SCRATCH=$(mktemp -d)

case "$(docker info --format '{{.Architecture}}')" in
  aarch64) PLATFORM=linux-aarch64 ;;
  x86_64) PLATFORM=linux-x86_64 ;;
  *) echo "意外的 Docker 架构，无法选择分发平台" >&2; exit 1 ;;
esac

for bin in hzd hz hz-coord; do
  if [ ! -f "$DIST_DIR/$PLATFORM/$bin" ]; then
    echo "缺少 $DIST_DIR/$PLATFORM/${bin}（先完成 musl release 构建并拷入 dist 目录）" >&2
    exit 1
  fi
done

cleanup_containers() {
  docker rm -f "$COORD" "$NODE" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup() {
  cleanup_containers
  rm -rf "$SCRATCH"
}
rc=0
trap 'rc=$?; if [ $rc -ne 0 ]; then
  docker exec "$COORD" cat /tmp/coord.log 2>/dev/null || true
  docker exec "$NODE" cat /tmp/hzd.log 2>/dev/null || true
  docker exec "$NODE" /usr/local/bin/hz status 2>&1 || true
fi
cleanup' EXIT

# 只清上次残留的容器与网络；SCRATCH 要留给本次 docker bind mount 用
cleanup_containers
docker network create "$NET" >/dev/null

docker run -d --name "$COORD" --network "$NET" --hostname coord \
  -v "$DIST_DIR:/dist:ro" -v "$SCRATCH:/data" \
  debian:bookworm sleep infinity >/dev/null

COORD_BIN="/dist/$PLATFORM/hz-coord"
docker exec -d "$COORD" sh -c "$COORD_BIN serve \
  --db /data/coord.db --listen 0.0.0.0:$GRPC_PORT --http-listen 0.0.0.0:$HTTP_PORT \
  --dist-dir /dist --public-url http://coord:$HTTP_PORT --public-grpc-addr http://coord:$GRPC_PORT \
  --metrics-listen off > /tmp/coord.log 2>&1"

BOOTSTRAP=$(docker exec "$COORD" "$COORD_BIN" bootstrap --db /data/coord.db --auth-key-expiry 1d --json)
AUTH_KEY=$(printf '%s' "$BOOTSTRAP" | sed -n 's/.*"auth_key":"\([^"]*\)".*/\1/p')
[ -n "$AUTH_KEY" ] || { echo "bootstrap 未返回 auth_key：$BOOTSTRAP" >&2; exit 1; }

docker run -d --name "$NODE" --network "$NET" --hostname fresh-host --privileged \
  debian:bookworm sleep infinity >/dev/null

docker exec "$NODE" sh -c 'apt-get update -qq >/dev/null && apt-get install -y -qq curl ca-certificates >/dev/null'

for _ in $(seq 1 30); do
  docker exec "$NODE" curl -fsS "http://coord:$HTTP_PORT/healthz" >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$NODE" curl -fsS "http://coord:$HTTP_PORT/healthz" >/dev/null

docker exec "$NODE" sh -c "curl -fsSL http://coord:$HTTP_PORT/install.sh | sh"
docker exec "$NODE" test -x /usr/local/bin/hzd
docker exec "$NODE" test -x /usr/local/bin/hz
docker exec "$NODE" test -f /etc/systemd/system/hzd.service
docker exec "$NODE" grep -q "^HZD_COORD_ADDR=http://coord:$GRPC_PORT\$" /etc/default/hzd
docker exec "$NODE" grep -q "^export HZD_COORD_ADDR=http://coord:$GRPC_PORT\$" /etc/profile.d/hznet.sh
echo "PASS: 一条命令安装（hzd/hz 落盘 + hzd.service + /etc/default/hzd）"

docker exec -d "$NODE" sh -c 'set -a; . /etc/default/hzd; set +a; exec /usr/local/bin/hzd > /tmp/hzd.log 2>&1'
for _ in $(seq 1 30); do
  docker exec "$NODE" test -S /var/run/hzd.sock 2>/dev/null && break
  sleep 1
done
docker exec "$NODE" test -S /var/run/hzd.sock
echo "PASS: 按 hzd.service 的 ExecStart 手动拉起 hzd，UDS 就绪（容器内无 systemd）"

UP_OUT=$(docker exec "$NODE" /usr/local/bin/hz up --auth-key "$AUTH_KEY")
printf '%s\n' "$UP_OUT" | grep -q "注册成功"
echo "PASS: hz up --auth-key 注册成功"
STATUS_OUT=$(docker exec "$NODE" /usr/local/bin/hz status)
grep -q "已加入 HzNet" <<<"$STATUS_OUT"
echo "PASS: hz status 显示已加入 HzNet"

# 模拟用户按安装手册第 6 节补过 Relay 地址：重装（升级）后应原样保留，
# HZD_COORD_ADDR 仍只有一行
docker exec "$NODE" sh -c 'echo HZD_RELAY_ADDR=https://relay.example:8443 >> /etc/default/hzd'
docker exec "$NODE" sh -c "curl -fsSL http://coord:$HTTP_PORT/install.sh | sh" >/dev/null
echo "PASS: 重复执行 install.sh 幂等（RC=0）"
docker exec "$NODE" grep -qx 'HZD_RELAY_ADDR=https://relay.example:8443' /etc/default/hzd
[ "$(docker exec "$NODE" grep -c '^HZD_COORD_ADDR=' /etc/default/hzd)" = 1 ]
docker exec "$NODE" grep -q "^HZD_COORD_ADDR=http://coord:$GRPC_PORT\$" /etc/default/hzd
echo "PASS: 重装保留 /etc/default/hzd 中已有的 HZD_RELAY_ADDR"

cp "$DIST_DIR/$PLATFORM/hz" "$SCRATCH/hz.bak"
printf x >> "$DIST_DIR/$PLATFORM/hz"
if TAMPER_OUT=$(docker exec "$NODE" sh -c "curl -fsSL http://coord:$HTTP_PORT/install.sh | sh" 2>&1); then
  mv "$SCRATCH/hz.bak" "$DIST_DIR/$PLATFORM/hz"
  echo "FAIL: 篡改后的二进制未被拒绝" >&2
  exit 1
fi
mv "$SCRATCH/hz.bak" "$DIST_DIR/$PLATFORM/hz"
printf '%s\n' "$TAMPER_OUT" | grep -q "校验失败"
echo "PASS: sha256 校验拒绝被篡改的二进制"

echo "ALL PASS"
