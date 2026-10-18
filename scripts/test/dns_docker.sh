#!/usr/bin/env bash
# M1 网内名字解析门禁（FR-5，issue #14）：docker 网络上一台 hz-coord + 两台 Linux Node。
# node1 走默认后缀 hznet.internal + resolv.conf 显式退路（HZD_DNS_RESOLVCONF_FALLBACK=1），
# node2 用 HZNET_DNS_SUFFIX=corp.mesh 验证后缀可配置。
# 通过标准：<对端 NodeName>.<suffix> 能 ping 通（v4 与 v6）；
# dig @100.96.0.53 只应答 HzNet 后缀（github.com → REFUSED）；
# 原解析器（127.0.0.11）在 hzd 运行期间照常可用；
# hzd 停止后 resolv.conf 逐字节还原、100.96.0.53:53 不再应答。
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NETWORK=hz-dns-test
COORD=hz-dns-coord
NODE1=hz-dns-n1
NODE2=hz-dns-n2
VOL_BIN=hz-dns-bin
VOL_TGT=hz-dns-build
CARGO_CACHE="${HZMN_CARGO_CACHE:-/Users/lixin/Develop/.hmn-cache/cargo}"
IMAGE="${HZMN_IMAGE:-rust:1-bookworm}"
MAP_WAIT_SECS=90

FAILURES=0

note() { printf '\n[dns-test] %s\n' "$*"; }
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

cleanup() {
  local dump="${1:-}"
  if [[ "$dump" == "dump" && "$FAILURES" -gt 0 ]]; then
    note "===== 失败现场 ====="
    for c in "$NODE1" "$NODE2"; do
      echo "--- $c hzd 日志 ---"
      docker exec "$c" sh -c 'cat /tmp/hzd.log 2>/dev/null | tail -40' || true
      echo "--- $c resolv.conf ---"
      docker exec "$c" cat /etc/resolv.conf || true
      echo "--- $c ip addr ---"
      docker exec "$c" ip addr || true
      echo "--- $c ip route ---"
      docker exec "$c" ip route || true
    done
    echo "--- coord 日志 ---"
    docker logs "$COORD" 2>&1 | tail -30 || true
  fi
  for c in "$COORD" "$NODE1" "$NODE2"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  docker volume rm "$VOL_BIN" >/dev/null 2>&1 || true
  docker volume rm "$VOL_TGT" >/dev/null 2>&1 || true
}
trap 'cleanup dump' EXIT

peer_field() {
  local node="$1" field="$2"
  docker exec -e HZD_SOCK_PATH=/tmp/hzd.sock "$node" /out/hz status --json 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); p=d["peers"][0]; print(p["'"$field"'"])'
}

wait_for_peer() {
  local node="$1" other="$2"
  for _ in $(seq 1 $((MAP_WAIT_SECS * 2))); do
    if docker exec -e HZD_SOCK_PATH=/tmp/hzd.sock "$node" /out/hz status --json 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    peers = d.get("peers") or []
    assert len(peers) == 1, f"期望恰好 1 个对端，实际 {len(peers)}"
    p = peers[0]
    assert p["name"] == "'"$other"'", p["name"]
    assert p["ipv4"] and p["ipv6"] and p["endpoints"], p
except Exception:
    sys.exit(1)
sys.exit(0)
' ; then return 0; fi
    sleep 0.5
  done
  return 1
}

wait_hzd_gone() {
  local node="$1"
  for _ in $(seq 1 30); do
    docker exec "$node" pgrep -x hzd >/dev/null 2>&1 || return 0
    sleep 0.5
  done
  return 1
}

note "清理旧环境并创建 docker 网络 $NETWORK"
cleanup nodump >/dev/null 2>&1 || true
docker network create "$NETWORK" >/dev/null
docker volume create "$VOL_BIN" >/dev/null
docker volume create "$VOL_TGT" >/dev/null

note "coord 容器：构建 release 二进制 + bootstrap 两把可复用 Auth Key + 启动 serve"
docker run -d --name "$COORD" --network "$NETWORK" \
  -v "$ROOT:/src" -v "$CARGO_CACHE:/usr/local/cargo/registry" -v "$VOL_BIN:/out" \
  -v "$VOL_TGT:/target" -w /src -e CARGO_TARGET_DIR=/target \
  "$IMAGE" bash -c '
    set -euo pipefail
    apt-get update -qq && apt-get install -y -qq iproute2 iputils-ping dnsutils python3 >/dev/null
    cargo build --release -p hz-coord -p hzd -p hz 2>&1 | tail -3
    cp /target/release/hz-coord /target/release/hzd /target/release/hz /out/
    /out/hz-coord bootstrap --db /tmp/hz.db --auth-key-expiry 1d --json > /tmp/key1.json
    /out/hz-coord bootstrap --db /tmp/hz.db --auth-key-expiry 1d --json > /tmp/key2.json
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

note "两个特权 Node 容器（/dev/net/tun）"
for i in 1 2; do
  name=$(eval "echo \$NODE$i")
  docker run -d --name "$name" --network "$NETWORK" --privileged --hostname "hznode$i" \
    -v "$VOL_BIN:/out" "$IMAGE" bash -c '
      set -euo pipefail
      apt-get update -qq && apt-get install -y -qq iproute2 iputils-ping dnsutils procps python3 >/dev/null
      [ -c /dev/net/tun ] || { mkdir -p /dev/net && mknod /dev/net/tun c 10 200; }
      sysctl -q net.ipv6.conf.all.disable_ipv6=0 2>/dev/null || true
      sleep infinity
    ' >/dev/null 2>&1
done

start_daemon() {
  local node="$1" suffix="$2"
  for _ in $(seq 1 120); do
    docker exec "$node" sh -c 'command -v ip >/dev/null && command -v dig >/dev/null && command -v ping >/dev/null' 2>/dev/null && break
    sleep 1
  done
  docker exec "$node" sh -c 'command -v ip >/dev/null' || { fail "$node 的 ip 命令未就绪"; return 1; }
  docker exec -d "$node" bash -c "
    export HZD_STATE_DIR=/tmp/hzd-state HZD_SOCK_PATH=/tmp/hzd.sock \
           HZD_COORD_ADDR=http://$COORD:443 HZD_WG_PORT=51820 \
           HZD_DNS_RESOLVCONF_FALLBACK=1 HZNET_DNS_SUFFIX=$suffix
    mkdir -p \$HZD_STATE_DIR
    exec /out/hzd > /tmp/hzd.log 2>&1
  "
  for _ in $(seq 1 40); do
    docker exec "$node" test -S /tmp/hzd.sock 2>/dev/null && break
    sleep 0.5
  done
}

register_node() {
  local node="$1" key="$2"
  docker exec -e HZD_SOCK_PATH=/tmp/hzd.sock "$node" /out/hz up --auth-key "$key" \
    || { fail "$node 注册失败"; docker exec "$node" tail -5 /tmp/hzd.log 2>/dev/null; }
}

note "node1 起 hzd（默认后缀 hznet.internal）；resolv.conf 快照在注册前拍"
RESOLV_BEFORE=/tmp/hz-dns-resolv.before
start_daemon "$NODE1" "hznet.internal"
docker exec "$NODE1" cat /etc/resolv.conf > "$RESOLV_BEFORE" || { fail "无法快照 node1 resolv.conf"; exit 1; }
register_node "$NODE1" "$KEY1"
note "node2 起 hzd 并注册（自定义后缀 corp.mesh）"
start_daemon "$NODE2" "corp.mesh"
register_node "$NODE2" "$KEY2"

note "等待两端的 Network Map 都出现对方（快照周期最长 ${MAP_WAIT_SECS}s）"
if wait_for_peer "$NODE1" "hznode2" && wait_for_peer "$NODE2" "hznode1"; then
  pass "双方 Network Map 互见（name/ipv4/ipv6/endpoints 齐全）"
else
  fail "Network Map 未在 ${MAP_WAIT_SECS}s 内互通"
  for node in "$NODE1" "$NODE2"; do
    docker exec -e HZD_SOCK_PATH=/tmp/hzd.sock "$node" /out/hz status --json 2>&1 | head -20 || true
  done
fi
IPV4_OF_NODE2=$(peer_field "$NODE1" ipv4)
IPV6_OF_NODE2=$(peer_field "$NODE1" ipv6)
IPV4_OF_NODE1=$(peer_field "$NODE2" ipv4)
note "node2=${IPV4_OF_NODE2} / ${IPV6_OF_NODE2}; node1=${IPV4_OF_NODE1}"

note "断言 1：本地 DNS 应答地址 100.96.0.53 已挂到 hz0（本地路由，不进 TUN）"
for node in "$NODE1" "$NODE2"; do
  addr=$(docker exec "$node" ip addr show dev hz0 2>/dev/null | grep -c '100.96.0.53/32')
  if [[ "$addr" == "1" ]]; then
    pass "${node}：hz0 持有 100.96.0.53/32"
  else
    fail "${node}：hz0 上找不到 100.96.0.53/32"
  fi
done

note "断言 2：dig @100.96.0.53 返回 Network Map 里的字面地址"
short=$(docker exec "$NODE1" dig +short @100.96.0.53 hznode2.hznet.internal A 2>/dev/null | tail -1)
if [[ "$short" == "$IPV4_OF_NODE2" ]]; then
  pass "A 记录 = ${short}（与 hz status 的 ipv4 一致）"
else
  fail "A 记录异常：dig=$short 期望=$IPV4_OF_NODE2"
fi
short6=$(docker exec "$NODE1" dig +short @100.96.0.53 hznode2.hznet.internal AAAA 2>/dev/null | tail -1)
if [[ "$short6" == "$IPV6_OF_NODE2" ]]; then
  pass "AAAA 记录 = $short6"
else
  fail "AAAA 记录异常：dig=$short6 期望=$IPV6_OF_NODE2"
fi

note "断言 3：resolv.conf 退路生效（本服务 nameserver 置顶 + search 合并后缀）"
if docker exec "$NODE1" sh -c 'grep -q "^nameserver 100.96.0.53" /etc/resolv.conf && grep -q "^search hznet.internal" /etc/resolv.conf'; then
  pass "node1 resolv.conf 已接管（nameserver 100.96.0.53 置顶）"
else
  fail "node1 resolv.conf 未按预期改写：$(docker exec "$NODE1" cat /etc/resolv.conf | tr '\n' ' ')"
fi

ping_name_assert() {
  local node="$1" target="$2" label="$3"
  local -a flags=()
  if (( $# > 3 )); then flags=("${@:4}"); fi
  local attempt
  for attempt in 1 2 3 4 5; do
    if docker exec "$node" ping ${flags[@]+"${flags[@]}"} -c 3 -W 2 "$target" >/tmp/hz-dns-ping.out 2>&1; then
      pass "${label}（第 ${attempt} 次尝试，$(grep -c 'bytes from' /tmp/hz-dns-ping.out)/3 应答）"
      return 0
    fi
    sleep 3
  done
  fail "${label}: $(tail -3 /tmp/hz-dns-ping.out | tr '\n' ' ')"
}

note "断言 4：<对端 NodeName>.hznet.internal 能 ping 通（v4 与 v6，走系统解析链路）"
ping_name_assert "$NODE1" "hznode2.hznet.internal" "node1 → hznode2.hznet.internal IPv4（AC-1）"
ping_name_assert "$NODE1" "hznode2.hznet.internal" "node1 → hznode2.hznet.internal IPv6" -6

note "断言 5：非 HzNet 域名不经过 hzd（github.com → REFUSED，不递归）"
status=$(docker exec "$NODE1" dig +time=2 +tries=1 @100.96.0.53 github.com A 2>/dev/null | grep -o 'status: [A-Z]*' | head -1)
if [[ "$status" == "status: REFUSED" ]]; then
  pass "dig @100.96.0.53 github.com → REFUSED（AC-2）"
else
  fail "dig @100.96.0.53 github.com 状态异常：${status:-无应答}"
fi

note "断言 6：hzd 运行期间原解析器（127.0.0.11）照常可用"
origin_status=$(docker exec "$NODE1" dig +time=2 +tries=1 @127.0.0.11 "$COORD" A 2>/dev/null | grep -o 'status: [A-Z]*' | head -1)
origin_answer=$(docker exec "$NODE1" dig +short +time=2 +tries=1 @127.0.0.11 "$COORD" A 2>/dev/null | grep -c '^10\.\|^172\.\|^192\.168\.')
if [[ "$origin_status" == "status: NOERROR" && "$origin_answer" -ge 1 ]]; then
  pass "原解析器仍能解析 ${COORD}（${origin_status}）"
else
  fail "原解析器异常：status=${origin_status:-无应答}"
fi

note "断言 7：域名后缀可配置（node2 用 corp.mesh）"
short_custom=$(docker exec "$NODE2" dig +short @100.96.0.53 hznode1.corp.mesh A 2>/dev/null | tail -1)
if [[ "$short_custom" == "$IPV4_OF_NODE1" ]]; then
  pass "dig @100.96.0.53 hznode1.corp.mesh → ${short_custom}（AC-4）"
else
  fail "自定义后缀解析异常：dig=$short_custom 期望=$IPV4_OF_NODE1"
fi
ping_name_assert "$NODE2" "hznode1.corp.mesh" "node2 → hznode1.corp.mesh IPv4（AC-4）"
refused_old=$(docker exec "$NODE2" dig +time=2 +tries=1 @100.96.0.53 hznode1.hznet.internal A 2>/dev/null | grep -o 'status: [A-Z]*' | head -1)
if [[ "$refused_old" == "status: REFUSED" ]]; then
  pass "node2 对默认后缀不越权应答（REFUSED）"
else
  fail "node2 不应答默认后缀却返回：${refused_old:-无应答}"
fi

note "断言 8：hzd 停止后系统 DNS 恢复原样（AC-3）"
docker exec "$NODE1" pkill -TERM hzd
if wait_hzd_gone "$NODE1"; then
  pass "node1 hzd 已按 SIGTERM 停止"
else
  fail "node1 hzd 未在 15s 内退出"
fi
RESOLV_AFTER=/tmp/hz-dns-resolv.after
docker exec "$NODE1" cat /etc/resolv.conf > "$RESOLV_AFTER"
if cmp -s "$RESOLV_BEFORE" "$RESOLV_AFTER"; then
  pass "resolv.conf 与启动前逐字节一致"
else
  fail "resolv.conf 未还原：before=$(tr '\n' ' ' < "$RESOLV_BEFORE") after=$(tr '\n' ' ' < "$RESOLV_AFTER")"
fi
if docker exec "$NODE1" dig +time=2 +tries=1 @100.96.0.53 hznode2.hznet.internal A >/dev/null 2>&1; then
  fail "100.96.0.53:53 仍在应答"
else
  pass "100.96.0.53:53 不再应答"
fi
restore_status=$(docker exec "$NODE1" dig +time=2 +tries=1 @127.0.0.11 "$COORD" A 2>/dev/null | grep -o 'status: [A-Z]*' | head -1)
if [[ "$restore_status" == "status: NOERROR" ]]; then
  pass "停止后原解析器照常工作"
else
  fail "停止后原解析器异常：${restore_status:-无应答}"
fi
if docker exec "$NODE1" ip addr show dev hz0 >/dev/null 2>&1; then
  fail "hzd 停止后 hz0 仍存在"
else
  pass "hz0 随进程退出销毁（含 100.96.0.53/32）"
fi

note "===== 结果 ====="
if [[ "$FAILURES" -gt 0 ]]; then
  printf 'FAILED： %d 项断言未通过\n' "$FAILURES"
  exit 1
fi
printf 'PASSED： 网内名字解析（A/AAAA 字面应答、后缀隔离、原解析器共存、停止还原、后缀可配置）全部通过\n'
exit 0
