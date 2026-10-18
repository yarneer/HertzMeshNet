#!/usr/bin/env bash
# 模拟 Node 的上游网络变化（issue #9）：给 Node 所在 NAT 的出口换一个 WAN IP
# 并重建该 Node 的静态映射（公网 Endpoint 随之更换），同时把 Node 侧网卡改名
# eth0 → eth1（换 Wi-Fi 的接口名变化；hzd 的 SO_BINDTODEVICE 随之悬空，外层
# 收发 ENODEV——不改名的话 WireGuard 端点漫游会瞬间救活直连，旧路径
# "确实断了"就无从断言）。
# 在 topo.sh 拓扑之上操作：须在特权容器内、topo up 之后运行；不影响任何
# 默认流程，只有本脚本被显式调用才改拓扑。
#
# 不走"veth 搬进另一台 NAT"的路子：目标 NAT 里已有 Node 时，双方互访对方的
# 公网映射是 hairpin 流量，而拓扑为同 NAT Node 启用的桥端口隔离（实测连经
# 路由的 hairpin 也拦）使直连永远打不通，场景无法成立。换上游 WAN IP 语义
# 等价（出口 IP / NAT 映射更换）且双方仍在不同 NAT 后，直连重协商走真实的
# NAT 穿越路径。
#
# 用法：netmove.sh <node> [new-wan-ip] [new-ext-port]
# 默认新 WAN IP 203.0.113.21（TEST-NET-3 里原网段之外的地址，挂在原 NAT 的
# wan0 上）、新外端口 40211。完成后打印 Node 的新公网 Endpoint（ip:port）。
set -uo pipefail

STATE_DIR="${HZ_TOPO_STATE_DIR:-/tmp/hz-topo}"
WG_PORT="${HZ_TOPO_WG_PORT:-51820}"
NEW_WAN_DEFAULT="203.0.113.21"
NEW_EXT_DEFAULT="40211"

die() { printf 'netmove: 错误：%s\n' "$*" >&2; exit 2; }

nat_num_of() {
  case "$1" in
    fullcone) echo 1 ;;
    portrestricted) echo 2 ;;
    symmetric) echo 3 ;;
    *) die "未知 NAT 绑定 $1" ;;
  esac
}

[[ $# -ge 1 ]] || die "用法：netmove.sh <node> [new-wan-ip] [new-ext-port]"
node="$1"
new_wan="${2:-$NEW_WAN_DEFAULT}"
new_ext="${3:-$NEW_EXT_DEFAULT}"

reg="$STATE_DIR/state/nodes.reg"
[[ -f $reg ]] || die "注册表不存在（先 topo.sh up）：$reg"
row=$(awk -F'|' -v n="$node" '$1 == n { print; exit }' "$reg")
[[ -n $row ]] || die "节点 $node 不在注册表"
IFS='|' read -r _ att ns old_ip old_ext <<<"$row"
[[ $att != symmetric ]] || die "对称型 NAT 无静态映射，不支持本场景"
num=$(nat_num_of "$att")
nat="hz-nat$num"
wan_ip="203.0.113.1$num"
inner_cidr="192.168.1${num}.0/24"

# 1. Node 侧：换一块新网卡（全新 veth、新 ifindex、名字 eth1）——换 Wi-Fi 时
#    接口是另一个设备，地址也换（新 DHCP 租约的样子）。旧 socket 的
#    SO_BINDTODEVICE 指向已删除的 ifindex，外层收发 ENODEV（实测内核行为），
#    直到 hzd 重绑才恢复；只改名不换设备的话 ifindex 不变，WireGuard 端点
#    漫游会瞬间救活直连。地址必须换：conntrack 会按旧五元组保留旧 NAT 映射，
#    不换地址的话旧公网 Endpoint 一直活着，"出口更换"无从谈起。
peer="hz-v-nat${num}-n${node}"
new_ip="192.168.1${num}.20"
ip -n "$ns" link del eth0
ip link add "$peer" type veth peer name iftmp
ip link set "$peer" netns "$nat"
ip -n "$nat" link set "$peer" master hz-br-in up
ip link set iftmp netns "$ns"
ip -n "$ns" link set iftmp name eth1
ip -n "$ns" addr add "${new_ip}/24" dev eth1
ip -n "$ns" link set eth1 up
ip -n "$ns" route replace default via "192.168.1${num}.1"

# 2. NAT 侧：wan0 挂新 WAN IP；静态映射整体重建——被搬节点用新内网地址与
#    新公网 IP/端口，同 NAT 其他在册节点保持原映射，masquerade 兜底照旧
#    （nat 链首个命中即终止，静态规则必须先于兜底）。旧映射不再重建，指向
#    它的旧路径彻底失效。
nftns() { ip netns exec "$nat" nft "$@"; }
ip -n "$nat" addr add "${new_wan}/24" dev wan0 2>/dev/null || true
nftns flush chain ip "$nat" prerouting
nftns flush chain ip "$nat" postrouting
while IFS='|' read -r r_name r_att _ r_ip r_ext; do
  [[ $(nat_num_of "$r_att") == "$num" && "$r_ext" != "0" ]] || continue
  if [[ "$r_name" == "$node" ]]; then
    r_ip="$new_ip"
    nftns add rule ip "$nat" postrouting oifname '"wan0"' ip saddr "$r_ip" \
      udp sport "$WG_PORT" snat to "${new_wan}:${new_ext}"
    nftns add rule ip "$nat" prerouting iifname '"wan0"' ip daddr "$new_wan" \
      udp dport "$new_ext" dnat to "${r_ip}:${WG_PORT}"
  else
    nftns add rule ip "$nat" postrouting oifname '"wan0"' ip saddr "$r_ip" \
      udp sport "$WG_PORT" snat to "${wan_ip}:${r_ext}"
    nftns add rule ip "$nat" prerouting iifname '"wan0"' ip daddr "$wan_ip" \
      udp dport "$r_ext" dnat to "${r_ip}:${WG_PORT}"
  fi
done < "$reg"
nftns add rule ip "$nat" postrouting oifname '"wan0"' ip saddr "$inner_cidr" masquerade

echo "${new_wan}:${new_ext}"
