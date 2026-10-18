#!/usr/bin/env bash
# FR-6 / #6 宕机容忍门禁（docker 网络上一台 hz-coord + 三台 Linux Node）。
# 通过标准：
#   1. coord 宕机期间，node1→node2 的持续 ping 不断（数据面不依赖 coord）；
#   2. 宕机期间 `hz status` 仍从本地缓存列出对端；
#   3. coord 恢复后，node1 的 hzd 不重启即自动重连，后注册的 node3 对它可见。
# 缓存重启恢复（hzd 重启 + coord 不可达）与差量推送契约由 Seam B 回环测试覆盖。
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NETWORK=hz-map-outage-test
COORD=hz-map-coord-test
NODE1=hz-map-node1-test
NODE2=hz-map-node2-test
NODE3=hz-map-node3-test
VOL_BIN=hz-map-bin-t6
VOL_TGT=hz-map-build-t6
CARGO_CACHE="${HZMN_CARGO_CACHE:-/Users/lixin/Develop/.hmn-cache/cargo}"
IMAGE="${HZMN_IMAGE:-rust:1-bookworm}"
OUTAGE_SECS="${HZ_OUTAGE_SECS:-120}"
RECOVERY_WAIT_SECS=60

FAILURES=0

note() { printf '\n[map-outage] %s\n' "$*"; }
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

cleanup() {
  if [[ "$FAILURES" -gt 0 ]]; then
    note "===== 失败现场 ====="
    for c in "$NODE1" "$NODE2" "$NODE3"; do
      echo "--- $c hzd 日志（尾部 30 行） ---"
      docker exec "$c" sh -c 'tail -30 /tmp/hzd.log 2>/dev/null' || true
    done
    echo "--- coord 日志 ---"
    docker logs "$COORD" 2>&1 | tail -20 || true
  fi
  for c in "$COORD" "$NODE1" "$NODE2" "$NODE3"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  docker volume rm "$VOL_BIN" "$VOL_TGT" >/dev/null 2>&1 || true
}
trap 'cleanup' EXIT

note "清理旧环境并创建 docker 网络 $NETWORK"
for c in "$COORD" "$NODE1" "$NODE2" "$NODE3"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
docker network rm "$NETWORK" >/dev/null 2>&1 || true
docker volume create "$VOL_BIN" >/dev/null
docker volume create "$VOL_TGT" >/dev/null
docker network create "$NETWORK" >/dev/null

note "coord 容器：构建 release 二进制 + bootstrap 三把 Auth Key + 启动 serve"
docker run -d --name "$COORD" --network "$NETWORK" \
  -v "$ROOT:/src" -v "$CARGO_CACHE:/usr/local/cargo/registry" -v "$VOL_BIN:/out" \
  -v "$VOL_TGT:/target" -w /src -e CARGO_TARGET_DIR=/target \
  "$IMAGE" bash -c '
    set -euo pipefail
    # docker start 会重跑本脚本；/out 里的二进制正被 Node 容器运行（Text file busy），
    # 且密钥与数据库都在容器层持久化，二次起只做 serve。
    if [ ! -f /tmp/bootstrapped ]; then
      apt-get update -qq && apt-get install -y -qq iproute2 iputils-ping python3 >/dev/null
      cargo build --release -p hz-coord -p hzd -p hz 2>&1 | tail -3
      cp /target/release/hz-coord /target/release/hzd /target/release/hz /out/
      /out/hz-coord bootstrap --db /tmp/hz.db --auth-key-expiry 1d --json > /tmp/key1.json
      /out/hz-coord bootstrap --db /tmp/hz.db --auth-key-expiry 1d --json > /tmp/key2.json
      /out/hz-coord bootstrap --db /tmp/hz.db --auth-key-expiry 1d --json > /tmp/key3.json
      touch /tmp/bootstrapped
    fi
    exec /out/hz-coord serve --db /tmp/hz.db --listen 0.0.0.0:443
  ' >/dev/null 2>&1

note "等待二进制构建与服务就绪（首次约数分钟）"
for _ in $(seq 1 720); do
  if docker exec "$COORD" test -f /out/hzd 2>/dev/null && \
     docker exec "$COORD" /out/hz-coord bootstrap --help >/dev/null 2>&1; then
    break
  fi
  sleep 5
done
docker exec "$COORD" test -f /out/hzd || { fail "release 二进制构建超时"; exit 1; }
for _ in $(seq 1 60); do
  docker exec "$COORD" bash -c '</dev/tcp/127.0.0.1/443' 2>/dev/null && break
  sleep 1
done
docker exec "$COORD" bash -c '</dev/tcp/127.0.0.1/443' 2>/dev/null || { fail "hz-coord serve 未就绪"; exit 1; }
KEY1=$(docker exec "$COORD" python3 -c 'import json;print(json.load(open("/tmp/key1.json"))["auth_key"])')
KEY2=$(docker exec "$COORD" python3 -c 'import json;print(json.load(open("/tmp/key2.json"))["auth_key"])')
KEY3=$(docker exec "$COORD" python3 -c 'import json;print(json.load(open("/tmp/key3.json"))["auth_key"])')

note "三个特权 Node 容器（/dev/net/tun）"
for i in 1 2 3; do
  name=$(eval "echo \$NODE$i")
  docker run -d --name "$name" --network "$NETWORK" --privileged --hostname "hznode$i" \
    -v "$VOL_BIN:/out" "$IMAGE" bash -c '
      set -euo pipefail
      apt-get update -qq && apt-get install -y -qq iproute2 iputils-ping python3 >/dev/null
      [ -c /dev/net/tun ] || { mkdir -p /dev/net && mknod /dev/net/tun c 10 200; }
      sysctl -q net.ipv6.conf.all.disable_ipv6=0 2>/dev/null || true
      sleep infinity
    ' >/dev/null 2>&1
done

start_node() {
  local node="$1" key="$2"
  for _ in $(seq 1 120); do
    docker exec "$node" sh -c 'command -v ip >/dev/null && command -v ping >/dev/null' 2>/dev/null && break
    sleep 1
  done
  docker exec "$node" sh -c 'command -v ip >/dev/null' || { fail "$node 的 ip 命令未就绪"; return 1; }
  docker exec -d "$node" bash -c "
    export HZD_STATE_DIR=/tmp/hzd-state HZD_SOCK_PATH=/tmp/hzd.sock \
           HZD_COORD_ADDR=http://$COORD:443 HZD_WG_PORT=51820
    mkdir -p \$HZD_STATE_DIR
    /out/hzd > /tmp/hzd.log 2>&1
  "
  for _ in $(seq 1 40); do
    docker exec "$node" test -S /tmp/hzd.sock 2>/dev/null && break
    sleep 0.5
  done
  docker exec -e HZD_SOCK_PATH=/tmp/hzd.sock "$node" /out/hz up --auth-key "$key" \
    || { fail "$node 注册失败"; docker exec "$node" tail -5 /tmp/hzd.log 2>/dev/null; }
}

note "node1/node2 注册（各自 Auth Key）"
start_node "$NODE1" "$KEY1"
start_node "$NODE2" "$KEY2"

has_peer() {
  local node="$1" other="$2"
  docker exec -e HZD_SOCK_PATH=/tmp/hzd.sock "$node" /out/hz status --json 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    peers = d.get("peers") or []
    assert any(p["name"] == "'"$other"'" for p in peers), [p.get("name") for p in peers]
except Exception:
    sys.exit(1)
sys.exit(0)
'
}

wait_for_peer() {
  local node="$1" other="$2"
  for _ in $(seq 1 180); do
    if has_peer "$node" "$other"; then return 0; fi
    sleep 0.5
  done
  return 1
}

note "等待两端互见（差量推送应在秒级到达）"
if wait_for_peer "$NODE1" "hznode2" && wait_for_peer "$NODE2" "hznode1"; then
  pass "node1/node2 Network Map 互见"
else
  fail "node1/node2 未互见，后续断言不成立"
  exit 1
fi

IPV4_OF_NODE2=$(docker exec -e HZD_SOCK_PATH=/tmp/hzd.sock "$NODE1" /out/hz status --json 2>/dev/null \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print([p["ipv4"] for p in d["peers"] if p["name"]=="hznode2"][0])')
note "node2 的 Node Address：${IPV4_OF_NODE2}；在 node1 上启动持续 ping（1 次/秒）"
docker exec "$NODE1" ping -c 2 -W 2 "$IPV4_OF_NODE2" >/dev/null 2>&1 || fail "宕机前基线 ping 不通"
docker exec -d "$NODE1" bash -c "while true; do ping -c 1 -W 2 '$IPV4_OF_NODE2' >/dev/null 2>&1 && echo ok || echo fail; sleep 1; done > /tmp/outage-ping.log"

note "宕机开始：停掉 coord 容器，持续 ${OUTAGE_SECS}s"
docker stop "$COORD" >/dev/null

sample=0
while (( sample * 20 < OUTAGE_SECS )); do
  sleep 20
  sample=$((sample + 1))
  elapsed=$((sample * 20))
  if docker exec "$NODE1" ping -c 3 -W 2 "$IPV4_OF_NODE2" >/dev/null 2>&1; then
    pass "宕机第 ${elapsed}s：node1→node2 ping 仍应答"
  else
    fail "宕机第 ${elapsed}s：ping 中断（数据面不应依赖 coord）"
  fi
  if docker exec -e HZD_SOCK_PATH=/tmp/hzd.sock "$NODE1" /out/hz status --json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert any(p["name"] == "hznode2" for p in d.get("peers") or []), d
' ; then
    pass "宕机第 ${elapsed}s：hz status 仍从缓存列出 hznode2"
  else
    fail "宕机第 ${elapsed}s：缓存里的对端丢失"
  fi
done

PING_FAILS=$(docker exec "$NODE1" sh -c 'grep -c fail /tmp/outage-ping.log 2>/dev/null || true')
PING_TOTAL=$(docker exec "$NODE1" sh -c 'wc -l < /tmp/outage-ping.log')
note "宕机窗口内 ping 统计：${PING_FAILS} 次失败 / ${PING_TOTAL} 次"
if docker exec "$NODE1" sh -c 'awk "BEGIN{x=0} /fail/{x++} END{exit x>=3?1:0}" /tmp/outage-ping.log'; then
  pass "持续 ping 全程无连续失败（会话不断）"
else
  fail "宕机期间出现连续 ping 失败"
fi

note "恢复 coord 容器"
docker start "$COORD" >/dev/null
for _ in $(seq 1 60); do
  docker exec "$COORD" bash -c '</dev/tcp/127.0.0.1/443' 2>/dev/null && break
  sleep 1
done
docker exec "$COORD" bash -c '</dev/tcp/127.0.0.1/443' 2>/dev/null || { fail "coord 恢复失败"; exit 1; }
pass "coord 已恢复（同一容器与数据库）"

note "注册 node3；断言 node1 的 hzd 不重启即看到它（重连退避上限 30s）"
start_node "$NODE3" "$KEY3"
seen_third=0
for _ in $(seq 1 $((RECOVERY_WAIT_SECS * 2))); do
  if has_peer "$NODE1" "hznode3"; then seen_third=1; break; fi
  sleep 0.5
done
if (( seen_third )); then
  pass "coord 恢复后 ${RECOVERY_WAIT_SECS}s 内，node1 未重启即看到新 Node hznode3"
else
  fail "node1 未在 ${RECOVERY_WAIT_SECS}s 内看到 hznode3（自动重连未生效）"
fi
if wait_for_peer "$NODE2" "hznode3"; then
  pass "node2（同样未重启）也看到 hznode3"
else
  fail "node2 未看到 hznode3"
fi
if docker exec "$NODE1" ping -c 3 -W 2 "$IPV4_OF_NODE2" >/dev/null 2>&1; then
  pass "恢复后 node1→node2 ping 仍通"
else
  fail "恢复后 ping 失败"
fi

note "===== 结果 ====="
if [[ "$FAILURES" -gt 0 ]]; then
  printf 'FAILED： %d 项断言未通过\n' "$FAILURES"
  exit 1
fi
printf 'PASSED： coord 宕机 %ss 期间 ping 不断、缓存可查；恢复后未重启的 hzd 自动重连并看到新 Node\n' "$OUTAGE_SECS"
exit 0
