#!/usr/bin/env bash
# M1 局域网互通门禁：docker 网络上一台 hz-coord + 两台 Linux Node（特权、/dev/net/tun）。
# 拓扑化（单容器 netns + NAT）版本见 scripts/test/topo/topo.sh，本脚本保留为多容器基线。
# 通过标准：两个方向都 ping 通对端 IPv4 与 ULA IPv6 Node Address；
# hz0 只接管 100.96.0.0/16 与 ULA /48（100.100.2.136 不走 hz0）；
# hzd 只持有唯一一个 UDP socket（打洞与 WireGuard 共用，ADR-0002）。
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NETWORK=hz-lan-test
COORD=hz-coord-test
NODE1=hz-node1-test
NODE2=hz-node2-test
VOL_BIN=hz-bin-test
VOL_TGT=hz-build-test
CARGO_CACHE="${HZMN_CARGO_CACHE:-/Users/lixin/Develop/.hmn-cache/cargo}"
IMAGE="${HZMN_IMAGE:-rust:1-bookworm}"
MAP_WAIT_SECS=90

FAILURES=0
declare -a LOGS

note() { printf '\n[lan-test] %s\n' "$*"; }
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

cleanup() {
  local dump="${1:-}"
  if [[ "$dump" == "dump" && "$FAILURES" -gt 0 ]]; then
    note "===== 失败现场 ====="
    for c in "$NODE1" "$NODE2"; do
      echo "--- $c hzd 日志 ---"
      docker exec "$c" sh -c 'cat /tmp/hzd.log 2>/dev/null | tail -40' || true
      echo "--- $c ip addr ---"
      docker exec "$c" ip addr || true
      echo "--- $c ip route ---"
      docker exec "$c" ip route || true
      docker exec "$c" ip -6 route || true
      echo "--- $c ss -u -a -p ---"
      docker exec "$c" ss -u -a -p || true
      echo "--- $c ss -t -n -p ---"
      docker exec "$c" ss -t -n -p || true
    done
    echo "--- coord 日志 ---"
    docker logs "$COORD" 2>&1 | tail -30 || true
  fi
  for c in "$COORD" "$NODE1" "$NODE2"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  docker volume rm "$VOL_BIN" >/dev/null 2>&1 || true
}
trap 'cleanup dump' EXIT

# 读取节点 status JSON 里第一个对端的字段（hz status --json 输出 IPC 原始结果）。
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
except Exception as e:
    sys.exit(1)
sys.exit(0)
' ; then return 0; fi
    sleep 0.5
  done
  return 1
}

ping_assert() {
  local node="$1" target="$2" label="$3"
  local -a flags=()
  if (( $# > 3 )); then flags=("${@:4}"); fi
  # 首个方向的第一次 ping 可能落在 WireGuard 冷启动握手的重传窗口内，允许重试。
  local attempt
  for attempt in 1 2 3 4 5; do
    if docker exec "$node" ping ${flags[@]+"${flags[@]}"} -c 3 -W 2 "$target" >/tmp/hz-ping.out 2>&1; then
      pass "${label}（第 ${attempt} 次尝试，$(grep -c 'bytes from' /tmp/hz-ping.out)/3 应答）"
      return 0
    fi
    sleep 3
  done
  fail "${label}: $(tail -3 /tmp/hz-ping.out | tr '\n' ' ')"
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
    apt-get update -qq && apt-get install -y -qq iproute2 iputils-ping python3 >/dev/null
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
      apt-get update -qq && apt-get install -y -qq iproute2 iputils-ping python3 >/dev/null
      # Docker Desktop 容器可能缺 /dev/net/tun；特权容器可直接 mknod 补上
      [ -c /dev/net/tun ] || { mkdir -p /dev/net && mknod /dev/net/tun c 10 200; }
      # 容器内核可能整体关闭了 IPv6，ULA 路由需要它
      sysctl -q net.ipv6.conf.all.disable_ipv6=0 2>/dev/null || true
      sleep infinity
    ' >/dev/null 2>&1
done

start_node() {
  local node="$1" key="$2"
  # 容器入口在后台 apt 安装 iproute2/ping；装完才能起 hzd（TUN 配置依赖 ip 命令）。
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
    || { fail "$node 注册失败"; docker exec "$node" cat /tmp/hzd.log 2>/dev/null | tail -5; }
}
note "node1/node2 注册（各自 Auth Key）"
start_node "$NODE1" "$KEY1"
start_node "$NODE2" "$KEY2"

note "等待两端的 Network Map 都出现对方（快照周期最长 ${MAP_WAIT_SECS}s）"
if wait_for_peer "$NODE1" "hznode2" && wait_for_peer "$NODE2" "hznode1"; then
  pass "双方 Network Map 互见（name/ipv4/ipv6/endpoints 齐全）"
else
  fail "Network Map 未在 ${MAP_WAIT_SECS}s 内互通"
  for node in "$NODE1" "$NODE2"; do
    echo "--- $node hz status --json ---"
    docker exec -e HZD_SOCK_PATH=/tmp/hzd.sock "$node" /out/hz status --json 2>&1 | head -30 || true
  done
fi

IPV4_OF_NODE2=$(peer_field "$NODE1" ipv4)
IPV6_OF_NODE2=$(peer_field "$NODE1" ipv6)
IPV4_OF_NODE1=$(peer_field "$NODE2" ipv4)
IPV6_OF_NODE1=$(peer_field "$NODE2" ipv6)
note "node2=${IPV4_OF_NODE2} / ${IPV6_OF_NODE2}; node1=${IPV4_OF_NODE1} / ${IPV6_OF_NODE1}"

# 共存场景（FR-7）：node1 上模拟一台接管默认路由的第三方 TUN 类网络工具。
# proxytun 没有读取者，等同黑洞；它同时吃掉默认路由与 docker 网段路由——
# 只黑洞默认路由时，同网段对端会走 eth0 的在链路由绕过黑洞，测不出绑定。
# hzd 的外层流量已绑物理出口网卡（SO_BINDTODEVICE），后续断言必须照常通过。
PROXY_SIM="${PROXY_SIM:-1}"
if [[ "$PROXY_SIM" == "1" ]]; then
  NODE2_LAN_IP=$(docker exec "$NODE2" hostname -i | awk '{print $1}')
  LAN_SUBNET=$(docker network inspect "$NETWORK" -f '{{(index .IPAM.Config 0).Subnet}}')
  note "PROXY_SIM：node1 安装黑洞 TUN（default 与 $LAN_SUBNET 均改道 proxytun）"
  if docker exec "$NODE1" sh -c "
      ip tuntap add dev proxytun mode tun &&
      ip addr add 198.18.0.1/30 dev proxytun &&
      ip link set proxytun up &&
      ip route replace default dev proxytun &&
      ip route replace $LAN_SUBNET dev proxytun
    "; then
    blackhole=$(docker exec "$NODE1" ip route get "$NODE2_LAN_IP" 2>/dev/null | head -1)
    if [[ "$blackhole" == *proxytun* ]]; then
      pass "黑洞生效：未绑定流量到 $NODE2_LAN_IP 已被第三方 TUN 吞下（${blackhole}）"
    else
      fail "黑洞未生效，共存场景不成立：$blackhole"
    fi
  else
    fail "第三方 TUN 模拟（proxytun）配置失败"
  fi
  estab=$(docker exec "$NODE1" sh -c "ss -t -n -p 2>/dev/null | grep hzd | grep -c ESTAB || true")
  if (( estab >= 1 )); then
    pass "node1：黑洞之下 hzd 与 Coordination Server 的 TCP 连接仍存活（ESTAB x${estab}）"
  else
    fail "node1：hzd 到 Coordination Server 的 TCP 连接丢失"
  fi
  if docker exec -e HZD_SOCK_PATH=/tmp/hzd.sock "$NODE1" /out/hz status >/dev/null 2>&1; then
    pass "node1：hz status 经本地 IPC 正常返回"
  else
    fail "node1：hz status 失败"
  fi
else
  note "PROXY_SIM=0：未安装第三方 TUN 模拟（基线路径）"
fi

# 主机名决定 Node Name 的规范化基名；hz status 的 name 已断言互见，这里直接 ping 地址。
note "断言 1：双向 IPv4 Node Address ping"
ping_assert "$NODE1" "$IPV4_OF_NODE2" "node1 → node2 IPv4 ($IPV4_OF_NODE2)"
ping_assert "$NODE2" "$IPV4_OF_NODE1" "node2 → node1 IPv4 ($IPV4_OF_NODE1)"

note "断言 2：双向 ULA IPv6 Node Address ping"
ping_assert "$NODE1" "$IPV6_OF_NODE2" "node1 → node2 IPv6 ($IPV6_OF_NODE2)" -6
ping_assert "$NODE2" "$IPV6_OF_NODE1" "node2 → node1 IPv6 ($IPV6_OF_NODE1)" -6

note "断言 3：hz0 只接管 HzNet 段（阿里云内网 DNS 100.100.2.136 不入隧道）"
for node in "$NODE1" "$NODE2"; do
  route=$(docker exec "$node" ip route get 100.100.2.136 2>/dev/null | head -1)
  if [[ "$route" != *hz0* ]]; then
    pass "${node}：100.100.2.136 不经 hz0（${route}）"
  else
    fail "${node}：100.100.2.136 被路由进 hz0：$route"
  fi
  hz_route=$(docker exec "$node" ip route show dev hz0 2>/dev/null)
  if [[ "$hz_route" == *"100.96.0.0/16"* ]] && [[ "$hz_route" != *"100.64.0.0/10"* ]]; then
    pass "${node}：hz0 仅接管 100.96.0.0/16（${hz_route}）"
  else
    fail "${node}：hz0 路由异常：$hz_route"
  fi
done

note "断言 4：hzd 仅持有唯一 UDP socket（WireGuard 与打洞共用，ADR-0002）"
for node in "$NODE1" "$NODE2"; do
  count=$(docker exec "$node" sh -c "ss -u -a -p 2>/dev/null | grep -c 'hzd' || true")
  if [[ "$count" == "1" ]]; then
    pass "${node}：hzd 恰好 1 个 UDP socket"
  else
    fail "${node}：hzd UDP socket 数量为 ${count}（应为 1）"
  fi
done

note "===== 结果 ====="
if [[ "$FAILURES" -gt 0 ]]; then
  printf 'FAILED： %d 项断言未通过\n' "$FAILURES"
  exit 1
fi
printf 'PASSED： 两节点局域网互通（v4+v6 双向）、路由边界、单 UDP socket 全部通过\n'
exit 0
