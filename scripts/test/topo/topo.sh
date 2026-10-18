#!/usr/bin/env bash
# Seam A NAT 测试拓扑（issue #5）：单个特权容器内用 network namespace + nftables
# 搭建模拟公网与三种 NAT 类型。场景以声明式 env 文件描述（scenarios/*.env），
# 本脚本是唯一解释器：up/down/run/selftest。命名前缀 hz- 保证 down 只清扫自有产物。
#
# 场景字段：
#   HZ_NODES     空格分隔的 name:attachment；attachment ∈ lan|fullcone|portrestricted|symmetric
#   HZ_ASSERT    断言套件名（suites.sh 里的 assert_suite_<name>）：lan|selftest|relay|none
#   HZ_COORD     1 则在 hz-wan 内构建并启动 Coordination Server
#   HZ_RELAY     1 则在 hz-wan 内启动 Relay（TLS 自签，coord 同机；默认 0，老场景不受影响）
#   HZ_REFLECTOR 1 则在 hz-wan 内启动 UDP 反射器（报告观测到的源端口）
#   HZ_PROXY_SIM 1 则在第一个 lan Node 内安装接管默认路由的黑洞 TUN（模拟第三方 TUN 类网络工具）
#   HZ_WG_PORT   Node UDP 端口（兼作锥形 NAT 的静态映射端口）
#   HZ_WAN_V6    1 则给 wan 平面与各 Node 配全球单播 IPv6（2001:db8::/32，
#                纯路由无 NAT），供 IPv6 Direct Path 场景用；默认 0，老场景不受影响
#   HZ_ISOLATE_LANPEERS 1 则把 NAT 内侧的 Node 桥端口设为 isolated：同类型 NAT
#                的多个 Node 不能经内桥 L2 直达（等价于各自独立的 NAT 设备），
#                直连只能走真正的 NAT 穿越；默认 0，老场景不受影响
set -uo pipefail

TOPO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$TOPO_DIR/../../.." && pwd)"
STATE_DIR="${HZ_TOPO_STATE_DIR:-/tmp/hz-topo}"
BIN_DIR="${HZ_TOPO_BIN_DIR:-/out}"
ART_DIR="" # 每次运行独立，见 main

WAN_NS=hz-wan
WAN_BR=hz-br-wan
WAN_CIDR=203.0.113.0/24      # TEST-NET-3
WAN_GW=203.0.113.1
LAN_BR=hz-br-lan
LAN_CIDR=192.168.100.0/24
LAN_GW=192.168.100.1
LAN_UPLINK=hz-v-lanup        # 根命名空间 → hz-wan 的上行 veth，无 NAT 纯路由
REFL_ADDR=$WAN_GW
REFL_PORT_A=19990
REFL_PORT_B=19991
UNSOLICIT_PORT=33333
RELAY_PORT=8443               # Relay TLS 监听端口（coord 占用 443）

FAILURES=0

note() { printf '\n[topo] %s\n' "$*"; }
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
die() { printf 'topo: 错误：%s\n' "$*" >&2; exit 2; }

require_root_netns() {
  # netns/nftables/tun 都要求特权容器；在普通容器或 macOS 主机上直接给出可读错误。
  [[ $EUID -eq 0 ]] || die "需要 root（请用 --privileged 容器运行）"
  ip netns list >/dev/null 2>&1 || die "ip netns 不可用（需要 --privileged 容器）"
  mkdir -p /var/run/netns 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 场景文件（域模型）：声明节点与 NAT 绑定，解释器据此建拓扑、选断言套件。
# ---------------------------------------------------------------------------
load_scenario() {
  local name="$1"
  local file="$TOPO_DIR/scenarios/$name.env"
  [[ -f $file ]] || die "场景不存在：$file"
  HZ_NODES=""; HZ_ASSERT="none"; HZ_COORD=0; HZ_RELAY=0; HZ_REFLECTOR=0; HZ_PROXY_SIM=0; HZ_WG_PORT=51820; HZ_WAN_V6=0; HZ_ISOLATE_LANPEERS=0
  # shellcheck disable=SC1090
  source "$file"
  [[ -n $HZ_NODES ]] || die "场景 $name 未声明 HZ_NODES"
  for spec in $HZ_NODES; do
    local node="${spec%%:*}" att="${spec##*:}"
    [[ "$node" =~ ^[a-z0-9]+$ ]] || die "节点名只允许小写字母数字：$node"
    case "$att" in
      lan|fullcone|portrestricted|symmetric) ;;
      *) die "未知 NAT 绑定 ${att}（节点 ${node}）" ;;
    esac
  done
}

# 运行期节点注册表：name|attachment|ns|inner_ip|ext_port
registry_file() { printf '%s/state/nodes.reg' "$STATE_DIR"; }

reg_add() { printf '%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" >> "$(registry_file)"; }
reg_list() { cat "$(registry_file)" 2>/dev/null; }
reg_field() { # reg_field <name> <field-idx 1..5>
  reg_list | awk -F'|' -v n="$1" -v f="$2" '$1 == n { print $f; exit }'
}

nat_num_of() { # fullcone→1 portrestricted→2 symmetric→3
  case "$1" in
    fullcone) echo 1 ;;
    portrestricted) echo 2 ;;
    symmetric) echo 3 ;;
  esac
}
node_ns() { echo "hz-node-$1"; }
node_hostname() { echo "hznode$1"; }

# ---------------------------------------------------------------------------
# 搭建 / 拆除
# ---------------------------------------------------------------------------
ns_exists() { ip netns list 2>/dev/null | cut -d' ' -f1 | grep -qx "$1"; }

sweep() {
  # down 的全部逻辑：按 hz- 前缀清扫自有产物，不触碰容器内其他网络对象。
  local ns pid link table round remaining
  for ns in $(ip netns list 2>/dev/null | cut -d' ' -f1 | grep '^hz-' || true); do
    for pid in $(ip netns pids "$ns" 2>/dev/null || true); do kill -9 "$pid" 2>/dev/null || true; done
  done
  # setsid 后台进程的 netns 释放是异步的，重试到删除成功为止（幂等的关键）
  for round in 1 2 3 4 5 6 7 8 9 10; do
    remaining=0
    for ns in $(ip netns list 2>/dev/null | cut -d' ' -f1 | grep '^hz-' || true); do
      ip netns del "$ns" 2>/dev/null || remaining=1
    done
    [[ $remaining -eq 0 ]] && break
    sleep 0.5
  done
  for link in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep '^hz-' || true); do
    ip link del "$link" 2>/dev/null || true
  done
  for table in $(nft list tables 2>/dev/null | awk '{print $2}' | grep '^hz-' || true); do
    nft delete table ip "$table" 2>/dev/null || true
  done
  return 0
}

ensure_tun_dev() {
  [[ -c /dev/net/tun ]] || { mkdir -p /dev/net && mknod /dev/net/tun c 10 200; }
}

ensure_wan() {
  ns_exists "$WAN_NS" && return 0
  ip netns add "$WAN_NS"
  ip -n "$WAN_NS" link set lo up
  ip -n "$WAN_NS" link add "$WAN_BR" type bridge
  ip -n "$WAN_NS" link set "$WAN_BR" up
  ip -n "$WAN_NS" addr add "$WAN_GW/24" dev "$WAN_BR"
  ip netns exec "$WAN_NS" sysctl -qw net.ipv4.ip_forward=1
}

ensure_lan() {
  # 局域网段放在容器根命名空间：节点同二层，经 LAN_UPLINK 纯路由（无 NAT）进 hz-wan。
  ip link show "$LAN_BR" >/dev/null 2>&1 && return 0
  ensure_wan
  ip link add "$LAN_BR" type bridge
  ip link set "$LAN_BR" up
  ip addr add "$LAN_GW/24" dev "$LAN_BR"
  ip link add "$LAN_UPLINK" type veth peer name hz-v-lanup-p
  ip link set hz-v-lanup-p netns "$WAN_NS"
  ip -n "$WAN_NS" link set hz-v-lanup-p name lanup0
  ip -n "$WAN_NS" link set lanup0 master "$WAN_BR" up
  ip addr add 203.0.113.2/24 dev "$LAN_UPLINK"
  ip link set "$LAN_UPLINK" up
  sysctl -qw net.ipv4.ip_forward=1
  ip -n "$WAN_NS" route add "$LAN_CIDR" via 203.0.113.2 2>/dev/null || true
}

ensure_nat() { # ensure_nat <num 1..3> <type>
  local num="$1" type="$2"
  local ns="hz-nat$num" wan_ip="203.0.113.1$num" inner="192.168.1$num.1"
  ns_exists "$ns" && return 0
  ensure_wan
  ip netns add "$ns"
  ip -n "$ns" link set lo up
  ip link add "hz-v-nat$num-w" type veth peer name "hz-v-nat$num-p"
  ip link set "hz-v-nat$num-p" netns "$ns"
  ip link set "hz-v-nat$num-w" netns "$WAN_NS"
  ip -n "$WAN_NS" link set "hz-v-nat$num-w" name "p-nat$num"
  ip -n "$WAN_NS" link set "p-nat$num" master "$WAN_BR" up
  ip -n "$ns" link set "hz-v-nat$num-p" name wan0
  ip -n "$ns" addr add "$wan_ip/24" dev wan0
  ip -n "$ns" link set wan0 up
  ip -n "$ns" link add hz-br-in type bridge
  ip -n "$ns" link set hz-br-in up
  ip -n "$ns" addr add "$inner/24" dev hz-br-in
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  ip -n "$ns" route add default via "$WAN_GW"
  config_nat_rules "$num" "$type" "$wan_ip"
}

# 每种 NAT 只写真正体现判别行为的最小 nftables 规则：
#  fullcone        静态 SNAT（固定外端口，映射与目标无关）+ 静态 DNAT，不设入站过滤
#  portrestricted  同样静态 SNAT/DNAT（映射与目标无关），但 forward 只放行 established
#  symmetric       masquerade fully-random（每条流独立随机外端口）+ 只放行 established
# 静态映射键在 HZ_WG_PORT：Node 的 UDP 端口固定（HZD_WG_PORT），天然可静态映射。
# nat 链首个命中即终止，所以静态 SNAT 规则必须先于 masquerade 兜底添加。
config_nat_rules() {
  local num="$1" type="$2" wan_ip="$3"
  local table="hz-nat$num" ns="hz-nat$num" row name att ipaddr extport
  nftns() { ip netns exec "$ns" nft "$@"; }
  nftns add table ip "$table"
  if [[ $type == symmetric ]]; then
    nftns add chain ip "$table" postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'
    nftns add rule ip "$table" postrouting oifname '"wan0"' ip saddr "192.168.1${num}.0/24" masquerade fully-random
    nftns add chain ip "$table" filterin '{ type filter hook forward priority filter; policy accept; }'
    nftns add rule ip "$table" filterin ct state established,related accept
    nftns add rule ip "$table" filterin iifname '"wan0"' drop
    return
  fi
  nftns add chain ip "$table" prerouting '{ type nat hook prerouting priority dstnat; policy accept; }'
  nftns add chain ip "$table" postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'
  nftns add chain ip "$table" filterin '{ type filter hook forward priority filter; policy accept; }'
  while IFS='|' read -r name att _ ipaddr extport _; do
    [[ $(nat_num_of "$att") == "$num" && $extport != 0 ]] || continue
    nftns add rule ip "$table" postrouting oifname '"wan0"' ip saddr "$ipaddr" \
      udp sport "$HZ_WG_PORT" snat to "${wan_ip}:${extport}"
    nftns add rule ip "$table" prerouting iifname '"wan0"' ip daddr "$wan_ip" \
      udp dport "$extport" dnat to "${ipaddr}:${HZ_WG_PORT}"
  done < <(reg_list)
  nftns add rule ip "$table" postrouting oifname '"wan0"' ip saddr "192.168.1${num}.0/24" masquerade
  if [[ $type == portrestricted ]]; then
    nftns add rule ip "$table" filterin ct state established,related accept
    nftns add rule ip "$table" filterin iifname '"wan0"' drop
  fi
}

# up 过程分两遍：先按场景声明注册节点（确定 IP/外端口），再建 NAT（规则依赖注册表）。
plan_nodes() {
  local spec name att
  local lan_idx=0 n1=0 n2=0 n3=0
  for spec in $HZ_NODES; do
    name="${spec%%:*}"; att="${spec##*:}"
    local ns ipaddr extport=0 num idx
    ns=$(node_ns "$name")
    if [[ $att == lan ]]; then
      lan_idx=$((lan_idx + 1))
      ipaddr="192.168.100.$((10 + lan_idx))"
    else
      num=$(nat_num_of "$att")
      case $num in 1) n1=$((n1 + 1)); idx=$n1 ;; 2) n2=$((n2 + 1)); idx=$n2 ;; 3) n3=$((n3 + 1)); idx=$n3 ;; esac
      ipaddr="192.168.1${num}.$((10 + idx))"
      if [[ $att != symmetric ]]; then
        extport=$((40000 + num * 100 + idx))
      fi
    fi
    reg_add "$name" "$att" "$ns" "$ipaddr" "$extport"
  done
}

build_fabric() {
  ensure_tun_dev
  ensure_wan
  local att
  local -A built=()
  for att in $(reg_list | cut -d'|' -f2); do
    if [[ $att != lan && -z ${built[$att]:-} ]]; then
      built[$att]=1
      ensure_nat "$(nat_num_of "$att")" "$att"
    fi
  done
  if grep -q '|lan|' "$(registry_file)"; then ensure_lan; fi
  if [[ $HZ_WAN_V6 == 1 ]]; then ensure_wan_v6; fi
}

# v6 平面（HZ_WAN_V6=1 时由 build_fabric 调用）：hz-wan 平面 2001:db8:f00::/64，
# 每个 NAT 内侧一个独立 /64，Node 侧静态地址 + 默认路由。IPv6 不做 NAT
# （FR-8：V6 Endpoint 无 NAT 预期），nft 规则都是 ip 族，不波及 v6 转发。
ensure_wan_v6() {
  ip netns exec "$WAN_NS" sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.all.forwarding=1
  ip -n "$WAN_NS" addr add "2001:db8:f00::1/64" dev "$WAN_BR" 2>/dev/null || true
  local num
  for num in 1 2 3; do
    ns_exists "hz-nat$num" || continue
    ip netns exec "hz-nat$num" sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.all.forwarding=1
    ip -n "hz-nat$num" addr add "2001:db8:f00::1${num}/64" dev wan0 2>/dev/null || true
    ip -n "hz-nat$num" addr add "2001:db8:${num}::1/64" dev hz-br-in 2>/dev/null || true
    ip -n "hz-nat$num" -6 route replace default via "2001:db8:f00::1" 2>/dev/null || true
    ip -n "$WAN_NS" -6 route replace "2001:db8:${num}::/64" via "2001:db8:f00::1${num}" 2>/dev/null || true
  done
  pass "IPv6 平面就绪（wan 2001:db8:f00::/64，NAT 内侧 2001:db8:N::/64，纯路由）"
}

# Node 侧 v6 地址（HZ_WAN_V6=1）：eth0 加全球单播地址 + 默认路由走 NAT 内侧网关。
config_node_v6() { # config_node_v6 <name> <nat-num> <host-suffix>
  local ns="hz-node-$1" num="$2" host="$3"
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=0 2>/dev/null || true
  ip -n "$ns" addr add "2001:db8:${num}::${host}/64" dev eth0 2>/dev/null || true
  ip -n "$ns" -6 route replace default via "2001:db8:${num}::1" 2>/dev/null || true
}

create_nodes() {
  local row name att ns ipaddr num peer
  while IFS='|' read -r row; do
    IFS='|' read -r name att ns ipaddr _ <<<"$row"
    ip netns add "$ns"
    ip -n "$ns" link set lo up
    if [[ $att == lan ]]; then
      peer="hz-v-$name"
      ip link add "$peer" type veth peer name hz-v-tmp
      ip link set hz-v-tmp netns "$ns"
      ip link set "$peer" master "$LAN_BR" up
    else
      num=$(nat_num_of "$att")
      peer="hz-v-nat$num-n$name"
      ip link add "$peer" type veth peer name hz-v-tmp
      ip link set hz-v-tmp netns "$ns"
      ip link set "$peer" netns "hz-nat$num"
      ip -n "hz-nat$num" link set "$peer" master hz-br-in up
      if [[ $HZ_ISOLATE_LANPEERS == 1 ]]; then
        ip netns exec "hz-nat$num" bridge link set dev "$peer" isolated on
      fi
    fi
    ip -n "$ns" link set hz-v-tmp name eth0
    ip -n "$ns" addr add "$ipaddr/24" dev eth0
    ip -n "$ns" link set eth0 up
    if [[ $att == lan ]]; then
      ip -n "$ns" route add default via "$LAN_GW"
    else
      ip -n "$ns" route add default via "192.168.1$(nat_num_of "$att").1"
    fi
    # hz0 的 ULA IPv6 依赖命名空间内 IPv6 可用（宿主内核可能默认关闭）
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0 2>/dev/null || true
    if [[ $HZ_WAN_V6 == 1 && $att != lan ]]; then
      config_node_v6 "$name" "$(nat_num_of "$att")" "${ipaddr##*.}"
    fi
  done < <(reg_list)
}

# ---------------------------------------------------------------------------
# 二进制 / Coordination Server / 反射器
# ---------------------------------------------------------------------------
build_binaries() {
  local bin
  for bin in hz-coord hz-relay hzd hz; do
    [[ -x $BIN_DIR/$bin ]] && continue
    command -v cargo >/dev/null 2>&1 || die "$BIN_DIR/$bin 缺失且无 cargo 可构建"
    note "构建 release 二进制到 ${BIN_DIR}（首次约数分钟）"
    (cd "$REPO_ROOT" && CARGO_TARGET_DIR="${HZ_TOPO_CARGO_TARGET_DIR:-/target}" \
       cargo build --release -p hz-coord -p hz-relay -p hzd -p hz || exit 1)
    local tgt="${HZ_TOPO_CARGO_TARGET_DIR:-/target}/release"
    mkdir -p "$BIN_DIR"
    cp "$tgt/hz-coord" "$tgt/hz-relay" "$tgt/hzd" "$tgt/hz" "$BIN_DIR/"
    return
  done
}

wait_tcp() { # wait_tcp <ns> <addr:port> <label>
  # 不用 bash /dev/tcp：Debian 的 bash 可能不带 net redirections（报 No such file or directory）
  local ns="$1" target="$2" label="$3" i
  local host="${target%%:*}" port="${target##*:}"
  for i in $(seq 1 60); do
    if ip netns exec "$ns" python3 -c '
import socket, sys
s = socket.socket(); s.settimeout(2)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
except OSError:
    sys.exit(1)
' "$host" "$port" 2>/dev/null; then return 0; fi
    sleep 1
  done
  fail "$label 未就绪（${target}）"
  return 1
}

start_coord() {
  local row name keyfile db="$ART_DIR/coord.db" first=1
  local -a relay_args=()
  while IFS='|' read -r row; do
    name=$(echo "$row" | cut -d'|' -f1)
    # Relay Token 只签发一次（meta 里只存哈希，后续 bootstrap 不覆盖）
    relay_args=()
    if [[ $HZ_RELAY == 1 && $first == 1 ]]; then relay_args=(--relay-token); fi
    ip netns exec "$WAN_NS" "$BIN_DIR/hz-coord" bootstrap --db "$db" \
      --auth-key-expiry 1d --json ${relay_args[@]+"${relay_args[@]}"} > "$ART_DIR/key-$name.json" || die "bootstrap $name 失败"
    first=0
  done < <(reg_list)
  ip netns exec "$WAN_NS" setsid "$BIN_DIR/hz-coord" serve --db "$db" --listen 0.0.0.0:443 \
    > "$ART_DIR/coord.log" 2>&1 &
  wait_tcp "$WAN_NS" "203.0.113.1:443" "Coordination Server" || return 1
  pass "Coordination Server 已在 $WAN_NS 启动（203.0.113.1:443）"
}

start_relay() {
  local first token
  first=$(reg_list | head -1 | cut -d'|' -f1)
  token=$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$first"'.json"))["relay_token"])')
  ip netns exec "$WAN_NS" setsid "$BIN_DIR/hz-relay" serve \
    --listen "0.0.0.0:$RELAY_PORT" --coord http://203.0.113.1:443 --relay-token "$token" \
    --tls-self-signed --tls-san 203.0.113.1 --tls-ca-out "$ART_DIR/relay-ca.pem" \
    > "$ART_DIR/relay.log" 2>&1 &
  wait_tcp "$WAN_NS" "203.0.113.1:$RELAY_PORT" "Relay" || return 1
  pass "Relay 已在 $WAN_NS 启动（203.0.113.1:${RELAY_PORT}，TLS 自签，CA 已写出）"
}

start_reflector() {
  # 对每个数据报回复观测到的源端口（十进制字符串），供 NAT 映射断言。
  ip netns exec "$WAN_NS" setsid python3 - > "$ART_DIR/reflector.log" 2>&1 <<PY &
import socket
socks = {}
for port in ($REFL_PORT_A, $REFL_PORT_B):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("$REFL_ADDR", port))
    s.settimeout(600)
    socks[port] = s
while True:
    for s in socks.values():
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            continue
        s.sendto(str(addr[1]).encode(), addr)
PY
  sleep 0.3
  ip netns pids "$WAN_NS" | grep -q . && pass "UDP 反射器已启动（$REFL_ADDR:$REFL_PORT_A/${REFL_PORT_B}）"
}

# ---------------------------------------------------------------------------
# 失败现场保全
# ---------------------------------------------------------------------------
dump_forensics() {
  local ns out="$ART_DIR/forensics.txt"
  {
    echo "===== 失败现场 $(date -u +%FT%TZ) ====="
    for ns in $(ip netns list | awk '{print $1}' | grep '^hz-' || true); do
      echo "--- $ns ip addr ---"; ip netns exec "$ns" ip addr 2>&1
      echo "--- $ns ip route ---"; ip netns exec "$ns" ip route 2>&1
      echo "--- $ns ip rule ---"; ip netns exec "$ns" ip rule 2>&1
      echo "--- $ns nft ruleset ---"; ip netns exec "$ns" nft list ruleset 2>&1
      echo "--- $ns ss -uapn ---"; ip netns exec "$ns" ss -uapn 2>&1
      echo "--- $ns ss -tnp ---"; ip netns exec "$ns" ss -tnp 2>&1
    done
    for f in "$ART_DIR"/*.log; do
      [[ -f $f ]] || continue
      echo "--- $(basename "$f") (tail 60) ---"; tail -60 "$f"
    done
  } | tee -a "$out"
}

# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------
cmd_up() {
  require_root_netns
  local scenario="$1"
  load_scenario "$scenario"
  mkdir -p "$STATE_DIR/state"
  : > "$(registry_file)"
  plan_nodes
  if [[ $HZ_COORD == 1 ]]; then build_binaries; fi
  build_fabric
  create_nodes
  if [[ $HZ_REFLECTOR == 1 ]]; then start_reflector; fi
  if [[ $HZ_COORD == 1 ]]; then start_coord || return 1; fi
  if [[ $HZ_RELAY == 1 ]]; then start_relay || return 1; fi
  note "拓扑已就绪：场景 ${scenario}（artifacts: ${ART_DIR}）"
}

cmd_run() {
  local scenario="$1" suite_rc=0
  ART_DIR="$STATE_DIR/run-$(date +%Y%m%d-%H%M%S)-$scenario"
  mkdir -p "$ART_DIR"
  cmd_up "$scenario" || { dump_forensics; sweep; return 1; }
  # shellcheck disable=SC1091
  source "$TOPO_DIR/suites.sh"
  "assert_suite_$HZ_ASSERT" || suite_rc=1
  if [[ $suite_rc -ne 0 ]]; then
    dump_forensics
    note "断言失败：现场已保存到 $ART_DIR/forensics.txt"
  fi
  sweep
  note "拓扑已拆除（重复执行 down/up 幂等）"
  return "$suite_rc"
}

cmd_down() {
  require_root_netns
  sweep
  note "已拆除全部 hz- 命名空间 / 链路 / nft 表"
}

cmd_selftest() { cmd_run selftest; }

usage() {
  cat <<'EOF'
用法：topo.sh <子命令>
  up <scenario>     搭建拓扑（scenarios/ 下的场景名）
  down              拆除全部 hz- 拓扑产物（幂等）
  run <scenario>    搭建 + 执行断言套件 + 拆除；失败时保留现场日志
  selftest          NAT 类型行为自检（fullcone/portrestricted/symmetric）
  build             只构建 hz-coord/hzd/hz 到 /out
  dump              打印当前各命名空间的失败现场信息
EOF
}

main() {
  local cmd="${1:-}"
  [[ -n $cmd ]] || { usage >&2; exit 2; }
  ART_DIR="$STATE_DIR/run-manual"
  mkdir -p "$ART_DIR"
  case "$cmd" in
    up) shift; [[ $# -eq 1 ]] || { usage >&2; exit 2; }; cmd_up "$1" ;;
    run) shift; [[ $# -eq 1 ]] || { usage >&2; exit 2; }; cmd_run "$1" ;;
    down) cmd_down ;;
    selftest) cmd_selftest ;;
    build) build_binaries ;;
    dump) require_root_netns; dump_forensics ;;
    *) usage >&2; exit 2 ;;
  esac
}

main "$@"
