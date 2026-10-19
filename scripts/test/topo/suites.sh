#!/usr/bin/env bash
# 断言套件：场景文件里 HZ_ASSERT 指向的 assert_suite_<name> 函数。
# 由 topo.sh 在源进程内加载，共享 pass/fail、注册表与场景变量。
# 只通过 hz 命令行与真实网络行为断言（Seam A 原则）。

hz_cli() { # hz_cli <node> <args...>
  local node="$1"; shift
  ip netns exec "$(node_ns "$node")" env HZD_SOCK_PATH="$ART_DIR/hzd-$node.sock" "$BIN_DIR/hz" "$@"
}

node_status_json() { # node_status_json <node>
  local ns; ns=$(node_ns "$1")
  ip netns exec "$ns" env HZD_SOCK_PATH="$ART_DIR/hzd-$1.sock" "$BIN_DIR/hz" status --json 2>/dev/null
}

peer_field() { # peer_field <node> <field>（取第一个对端）
  node_status_json "$1" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["peers"][0]["'"$2"'"])'
}

start_node_daemon() { # start_node_daemon <node> <auth-key>
  # 可选 HZD_NODE_EXTRA：额外注入 hzd 的环境变量串（relay 场景用它传
  # HZD_RELAY_ADDR/HZD_RELAY_CA_PATH/HZD_FORCE_RELAY）；未设置时为空，老场景不受影响。
  local name="$1" key="$2" ns hostname
  ns=$(node_ns "$name"); hostname=$(node_hostname "$name")
  mkdir -p "$ART_DIR/state-$name"
  # 各 Node 独立 UTS 命名空间决定注册用的主机名（容器内所有 netns 共享同一个）
  ip netns exec "$ns" setsid unshare --uts sh -c \
    "echo $hostname > /proc/sys/kernel/hostname; \
     exec env HZD_STATE_DIR=$ART_DIR/state-$name HZD_SOCK_PATH=$ART_DIR/hzd-$name.sock \
       HZD_COORD_ADDR=http://203.0.113.1:443 HZD_WG_PORT=$HZ_WG_PORT \
       ${HZD_NODE_EXTRA:-} $BIN_DIR/hzd" \
    > "$ART_DIR/hz-node-$name.log" 2>&1 &
  local i
  for i in $(seq 1 40); do
    ip netns exec "$ns" test -S "$ART_DIR/hzd-$name.sock" 2>/dev/null && break
    sleep 0.5
  done
  ip netns exec "$ns" test -S "$ART_DIR/hzd-$name.sock" || { fail "${name}：hzd socket 未出现"; return 1; }
  if hz_cli "$name" up --auth-key "$key" >/dev/null 2>&1; then
    pass "${name}：hz up --auth-key 注册成功"
  else
    fail "${name}：注册失败（见 $ART_DIR/hz-node-$name.log）"
    return 1
  fi
}

wait_for_peer() { # wait_for_peer <node> <expected-peer-name>
  local node="$1" other="$2" i
  for i in $(seq 1 180); do
    if node_status_json "$node" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    peers = d.get("peers") or []
    assert len(peers) == 1, f"期望恰好 1 个对端，实际 {len(peers)}"
    p = peers[0]
    assert p["name"] == "'"hznode$other"'", p["name"]
    assert p["ipv4"] and p["ipv6"] and p["endpoints"], p
except Exception:
    sys.exit(1)
sys.exit(0)
'; then return 0; fi
    sleep 0.5
  done
  return 1
}

ping_assert() { # ping_assert <node> <target> <label> [flags...]
  local node="$1" target="$2" label="$3" ns attempt
  ns=$(node_ns "$node")
  local -a flags=()
  if (( $# > 3 )); then flags=("${@:4}"); fi
  # 首个方向的第一次 ping 可能落在 WireGuard 冷启动握手的重传窗口内，允许重试。
  for attempt in 1 2 3 4 5; do
    if ip netns exec "$ns" ping ${flags[@]+"${flags[@]}"} -c 3 -W 2 "$target" > "$ART_DIR/ping.out" 2>&1; then
      pass "${label}（第 ${attempt} 次尝试，$(grep -c 'bytes from' "$ART_DIR/ping.out")/3 应答）"
      return 0
    fi
    sleep 3
  done
  fail "${label}: $(tail -3 "$ART_DIR/ping.out" | tr '\n' ' ')"
}

wait_for_log() { # wait_for_log <file> <pattern> <label> [timeout-secs]
  local file="$1" pattern="$2" label="$3" timeout="${4:-60}" i
  for i in $(seq 1 $((timeout * 2))); do
    if [[ -f $file ]] && grep -q "$pattern" "$file"; then
      pass "${label}（$(grep "$pattern" "$file" | tail -1 | cut -c1-160)）"
      return 0
    fi
    sleep 0.5
  done
  fail "${label}：${timeout}s 内未在 $(basename "$file") 见到 /$pattern/"
  return 1
}

relay_env_extra() { # 打洞/STUN 场景共用的 hzd 注入：Relay 地址 + 自签 CA（STUN 地址自动推导同主机 3478）
  echo "HZD_RELAY_ADDR=https://203.0.113.1:$RELAY_PORT HZD_RELAY_CA_PATH=$ART_DIR/relay-ca.pem"
}

start_pair_with_relay() { # start_pair_with_relay <a> <b>：带 Relay/STUN 启动并注册两个 Node
  local a="$1" b="$2"
  HZD_NODE_EXTRA="$(relay_env_extra)"
  note "[$a/$b] 启动 hzd（Relay + STUN，路径管理自选路径）并注册"
  start_node_daemon "$a" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$a"'.json"))["auth_key"])')" || return 1
  start_node_daemon "$b" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$b"'.json"))["auth_key"])')" || return 1
}

wait_pair_mutual_view() { # wait_pair_mutual_view <a> <b>
  if wait_for_peer "$1" "$2" && wait_for_peer "$2" "$1"; then
    pass "双方 Network Map 互见（name/ipv4/ipv6/endpoints 齐全）"
  else
    fail "Network Map 未在 90s 内互通"
    return 1
  fi
}

peer_addresses() { # peer_addresses <a> <b>：打印对端视角的 v4/v6 Node Address
  local b4 b6 a4 a6
  b4=$(peer_field "$1" ipv4); b6=$(peer_field "$1" ipv6)
  a4=$(peer_field "$2" ipv4); a6=$(peer_field "$2" ipv6)
  note "$2=${b4} / ${b6}；$1=${a4} / ${a6}"
}

assert_single_udp_socket() { # assert_single_udp_socket <node...>
  local node ns count
  for node in "$@"; do
    ns=$(node_ns "$node")
    count=$(ip netns exec "$ns" sh -c "ss -u -a -n -p 2>/dev/null | grep 'hzd' | grep -v '100\\.96\\.0\\.53:53' | grep -c . || true")
    if [[ $count == 1 ]]; then
      pass "${node}：hzd 恰好 1 个 UDP socket（WireGuard/打洞/STUN 共用，ADR-0002）"
    else
      fail "${node}：hzd 数据面 UDP socket 数量为 ${count}（应为 1，已排除 100.96.0.53:53 本地 DNS 应答）"
    fi
  done
}

# ---------------------------------------------------------------------------
# 套件 lan：ticket #4 局域网互通断言的拓扑化移植（HZ_PROXY_SIM=1 时加第三方 TUN 共存步骤）
# ---------------------------------------------------------------------------
assert_suite_lan() {
  local a b
  a=$(reg_list | awk -F'|' '$2 == "lan" { print $1; exit }')
  b=$(reg_list | awk -F'|' '$2 == "lan" && $1 != "'"$a"'" { print $1; exit }')
  [[ -n $a && -n $b ]] || { fail "场景需要恰好两个 lan 节点"; return 1; }

  note "[$a/$b] 启动 hzd 并注册"
  start_node_daemon "$a" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$a"'.json"))["auth_key"])')" || return 1
  start_node_daemon "$b" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$b"'.json"))["auth_key"])')" || return 1

  note "等待双方的 Network Map 互见"
  if wait_for_peer "$a" "$b" && wait_for_peer "$b" "$a"; then
    pass "双方 Network Map 互见（name/ipv4/ipv6/endpoints 齐全）"
  else
    fail "Network Map 未在 90s 内互通"
    node_status_json "$a" | head -20 || true
    node_status_json "$b" | head -20 || true
    return 1
  fi

  local a4 b4 a6 b6
  b4=$(peer_field "$a" ipv4); b6=$(peer_field "$a" ipv6)
  a4=$(peer_field "$b" ipv4); a6=$(peer_field "$b" ipv6)
  note "$b=${b4} / ${b6}；$a=${a4} / ${a6}"

  if [[ $HZ_PROXY_SIM == 1 ]]; then
    # 模拟接管默认路由的第三方 TUN 类网络工具：proxytun 无读取者即黑洞。
    # 只黑洞默认路由时，同网段对端会走 eth0 在链路由绕过黑洞，测不出共存，须连同 LAN 网段一起改道。
    # hzd 的外层流量已绑物理出口网卡（SO_BINDTODEVICE），后续断言必须照常通过。
    local b_lan_ip ns
    b_lan_ip=$(reg_field "$b" 4); ns=$(node_ns "$a")
    note "PROXY_SIM：$a 安装黑洞 TUN（default 与 $LAN_CIDR 均改道 proxytun）"
    if ip netns exec "$ns" sh -c "
        ip tuntap add dev proxytun mode tun &&
        ip addr add 198.18.0.1/30 dev proxytun &&
        ip link set proxytun up &&
        ip route replace default dev proxytun &&
        ip route replace $LAN_CIDR dev proxytun
      "; then
      local blackhole
      blackhole=$(ip netns exec "$ns" ip route get "$b_lan_ip" 2>/dev/null | head -1)
      if [[ $blackhole == *proxytun* ]]; then
        pass "黑洞生效：未绑定流量到 $b_lan_ip 已被第三方 TUN 吞下（${blackhole}）"
      else
        fail "黑洞未生效，共存场景不成立：$blackhole"
      fi
    else
      fail "第三方 TUN 模拟（proxytun）配置失败"
    fi
    local estab
    estab=$(ip netns exec "$ns" sh -c "ss -t -n -p 2>/dev/null | grep hzd | grep -c ESTAB || true")
    if (( estab >= 1 )); then
      pass "${a}：黑洞之下 hzd 与 Coordination Server 的 TCP 连接仍存活（ESTAB x${estab}）"
    else
      fail "${a}：hzd 到 Coordination Server 的 TCP 连接丢失"
    fi
    if hz_cli "$a" status >/dev/null 2>&1; then
      pass "${a}：hz status 经本地 IPC 正常返回"
    else
      fail "${a}：hz status 失败"
    fi
  fi

  note "断言 1：双向 IPv4 Node Address ping"
  ping_assert "$a" "$b4" "$a → $b IPv4（${b4}）"
  ping_assert "$b" "$a4" "$b → $a IPv4（${a4}）"

  note "断言 2：双向 ULA IPv6 Node Address ping"
  ping_assert "$a" "$b6" "$a → $b IPv6（${b6}）" -6
  ping_assert "$b" "$a6" "$b → $a IPv6（${a6}）" -6

  note "断言 3：hz0 只接管 HzNet 段（100.100.2.136 不入隧道）"
  local node ns route hz_route
  for node in "$a" "$b"; do
    ns=$(node_ns "$node")
    route=$(ip netns exec "$ns" ip route get 100.100.2.136 2>/dev/null | head -1)
    if [[ $route != *hz0* ]]; then
      pass "${node}：100.100.2.136 不经 hz0（${route}）"
    else
      fail "${node}：100.100.2.136 被路由进 hz0：$route"
    fi
    hz_route=$(ip netns exec "$ns" ip route show dev hz0 2>/dev/null)
    if [[ $hz_route == *"100.96.0.0/16"* && $hz_route != *"100.64.0.0/10"* ]]; then
      pass "${node}：hz0 仅接管 100.96.0.0/16（${hz_route}）"
    else
      fail "${node}：hz0 路由异常：$hz_route"
    fi
  done

  note "断言 4：hzd 仅持有唯一 UDP socket（WireGuard 与打洞共用，ADR-0002）"
  for node in "$a" "$b"; do
    ns=$(node_ns "$node")
    count=$(ip netns exec "$ns" sh -c "ss -u -a -n -p 2>/dev/null | grep 'hzd' | grep -v '100\\.96\\.0\\.53:53' | grep -c . || true")
    if [[ $count == 1 ]]; then
      pass "${node}：hzd 恰好 1 个 UDP socket"
    else
      fail "${node}：hzd 数据面 UDP socket 数量为 ${count}（应为 1，已排除 100.96.0.53:53 本地 DNS 应答）"
    fi
  done

  (( FAILURES == 0 ))
}

# ---------------------------------------------------------------------------
# 套件 selftest：三种 NAT 的判别行为（FR-8 断言可信度的基石）
# ---------------------------------------------------------------------------
nat_probe() { # nat_probe <node> → 输出 "对A观测端口 对B观测端口"（同一 socket、两个目标）
  local ns; ns=$(node_ns "$1")
  ip netns exec "$ns" python3 - <<PY
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", $HZ_WG_PORT)); s.settimeout(5)
s.sendto(b"probe", ("$REFL_ADDR", $REFL_PORT_A)); pa = int(s.recv(100))
s.sendto(b"probe", ("$REFL_ADDR", $REFL_PORT_B)); pb = int(s.recv(100))
print(pa, pb)
PY
}

unsolicited_knock() { # unsolicited_knock <nat-wan-ip> <port>：从 hz-wan 的独立端口发一个 UDP 包
  ip netns exec "$WAN_NS" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((\"$REFL_ADDR\", $UNSOLICIT_PORT))
s.sendto(b'knock', ('$1', $2))
"
}

unsolicited_listener() { # unsolicited_listener <node>：监听 ${HZ_WG_PORT}，输出 RECV 或 TIMEOUT
  local ns; ns=$(node_ns "$1")
  ip netns exec "$ns" timeout 5 python3 - <<PY
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", $HZ_WG_PORT)); s.settimeout(4)
try:
    data, addr = s.recvfrom(256); print("RECV", data.decode(), addr)
except socket.timeout:
    print("TIMEOUT")
PY
}

assert_suite_selftest() {
  local row name att ns ipaddr extport wanip pa pb out
  while IFS='|' read -r row; do
    IFS='|' read -r name att ns ipaddr extport _ <<<"$row"
    wanip="203.0.113.1$(nat_num_of "$att")"
    note "[$name / $att] 映射观测：同一 UDP socket 发往反射器两个端口"
    out=$(nat_probe "$name") || { fail "${name}：反射器探测无应答"; continue; }
    pa=${out% *}; pb=${out#* }
    case "$att" in
      fullcone)
        [[ $pa == "$extport" && $pb == "$extport" ]] \
          && pass "${name}：完全锥形——两个目标看到同一外端口 ${pa}（= 静态映射 ${extport}）" \
          || fail "${name}：完全锥形映射不稳定：$pa/$pb ≠ $extport"
        ;;
      portrestricted)
        [[ $pa == "$extport" && $pb == "$extport" ]] \
          && pass "${name}：端口受限——映射与目标无关（${pa} = ${extport}）" \
          || fail "${name}：端口受限映射不稳定：$pa/$pb ≠ $extport"
        ;;
      symmetric)
        [[ $pa != "$pb" ]] \
          && pass "${name}：对称型——两个目标看到不同外端口（$pa ≠ ${pb}）" \
          || fail "${name}：对称型未表现出按流变化：$pa == $pb"
        ;;
    esac

    note "[$name / $att] 未经请求的入站：从 hz-wan 第三方端口 ${UNSOLICIT_PORT} 敲映射端口"
    local target_port=$extport
    [[ $att == symmetric ]] && target_port=$pa
    unsolicited_listener "$name" > "$ART_DIR/unsol-$name.out" 2>&1 &
    local listener_pid=$!
    sleep 0.5
    unsolicited_knock "$wanip" "$target_port"
    wait "$listener_pid"
    out=$(cat "$ART_DIR/unsol-$name.out")
    case "$att" in
      fullcone)
        [[ $out == RECV* ]] \
          && pass "${name}：完全锥形——任意第三方入站直达 Node（${out}）" \
          || fail "${name}：完全锥形应放行任意入站，实际：$out"
        ;;
      portrestricted|symmetric)
        [[ $out == TIMEOUT ]] \
          && pass "${name}：$att——未见目标之外的入站被丢弃" \
          || fail "${name}：$att 不应放行第三方入站，实际：$out"
        ;;
    esac
  done < <(reg_list)
  (( FAILURES == 0 ))
}

assert_suite_none() { note "场景未声明断言套件（HZ_ASSERT=none）"; return 0; }

# ---------------------------------------------------------------------------
# 套件 relay：两端都在对称型 NAT 后，数据面经 Relay 互通（FR-9 / issue #7）
# ---------------------------------------------------------------------------
assert_suite_relay() {
  local a b node ns estab probe_out probe_rc
  a=$(reg_list | awk -F'|' '$2 == "symmetric" { print $1; exit }')
  b=$(reg_list | awk -F'|' '$2 == "symmetric" && $1 != "'"$a"'" { print $1; exit }')
  [[ -n $a && -n $b ]] || { fail "场景需要恰好两个 symmetric 节点"; return 1; }

  HZD_NODE_EXTRA="$(relay_env_extra)"
  note "[$a/$b] 启动 hzd（路径管理对对称 NAT 自选 Relay，无强制开关）并注册"
  start_node_daemon "$a" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$a"'.json"))["auth_key"])')" || return 1
  start_node_daemon "$b" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$b"'.json"))["auth_key"])')" || return 1

  note "等待双方的 Network Map 互见"
  if wait_for_peer "$a" "$b" && wait_for_peer "$b" "$a"; then
    pass "双方 Network Map 互见（name/ipv4/ipv6/endpoints 齐全）"
  else
    fail "Network Map 未在 90s 内互通"
    return 1
  fi

  local a4 b4 a6 b6
  b4=$(peer_field "$a" ipv4); b6=$(peer_field "$a" ipv6)
  a4=$(peer_field "$b" ipv4); a6=$(peer_field "$b" ipv6)
  note "$b=${b4} / ${b6}；$a=${a4} / ${a6}"

  note "断言 1：经 Relay 的双向 IPv4 Node Address ping"
  ping_assert "$a" "$b4" "$a → $b IPv4 经 Relay（${b4}）"
  ping_assert "$b" "$a4" "$b → $a IPv4 经 Relay（${a4}）"

  note "断言 2：经 Relay 的双向 ULA IPv6 ping（WG 加密任意 IP，中继不改路径语义）"
  ping_assert "$a" "$b6" "$a → $b IPv6 经 Relay（${b6}）" -6
  ping_assert "$b" "$a6" "$b → $a IPv6 经 Relay（${a6}）" -6

  note "断言 3：路径确实经过 Relay（双方各持一条到 $RELAY_PORT 的 ESTAB，会话各开一次）"
  for node in "$a" "$b"; do
    ns=$(node_ns "$node")
    estab=$(ip netns exec "$ns" sh -c "ss -t -n -p 2>/dev/null | grep hzd | grep -c ':$RELAY_PORT' || true")
    if (( estab >= 1 )); then
      pass "${node}：hzd 与 Relay 的 TLS 连接存活（ESTAB x${estab}）"
    else
      fail "${node}：hzd 到 Relay 的 TLS 连接缺失"
    fi
  done
  local opened
  opened=$(grep -c 'relay session opened' "$ART_DIR/relay.log" || true)
  if (( opened >= 2 )); then
    pass "Relay 侧两条会话登记在案（opened x${opened}）"
  else
    fail "Relay 会话登记数异常：${opened}（应 >= 2）"
  fi

  note "断言 4：未注册客户端被 Relay 拒绝（一次性 Machine Key 从 hz-wan 试探）"
  probe_rc=0
  probe_out=$(ip netns exec "$WAN_NS" "$BIN_DIR/hz-relay" probe \
    --addr "https://203.0.113.1:$RELAY_PORT" --ca "$ART_DIR/relay-ca.pem" --node-id intruder) || probe_rc=$?
  if (( probe_rc != 0 )) && [[ $probe_out == *"被拒绝"* ]]; then
    pass "未注册身份被拒：$probe_out"
  else
    fail "未注册身份应被拒绝（rc=${probe_rc}）：$probe_out"
  fi

  note "断言 5：Relay 日志只见密文帧（载荷带 pattern 的 ping 不在日志出现明文）"
  local pattern="beefcafe"
  ip netns exec "$(node_ns "$a")" ping -6 -c 2 -W 3 -p "$pattern" "$b6" > /dev/null 2>&1 || true
  if grep -q "$pattern" "$ART_DIR/relay.log"; then
    fail "Relay 日志出现明文载荷痕迹：$(grep "$pattern" "$ART_DIR/relay.log" | head -1)"
  else
    pass "Relay 日志无明文载荷（pattern ${pattern} 未出现）"
  fi

  unset HZD_NODE_EXTRA
  (( FAILURES == 0 ))
}

# ---------------------------------------------------------------------------
# 套件 direct（FR-8 / issue #8 AC1）：两端锥形 NAT，打洞成功升级 Direct Path
# ---------------------------------------------------------------------------
pick_two() { # pick_two <attachment>：按 attachment 取两个节点名
  local a b
  a=$(reg_list | awk -F'|' -v t="$1" '$2 == t { print $1; exit }')
  b=$(reg_list | awk -F'|' -v t="$1" '$2 == t && $1 != "'"$a"'" { print $1; exit }')
  echo "$a $b"
}

assert_suite_direct() {
  local a b b4 b6 a4 a6
  a=$(reg_list | awk -F'|' '$2 == "fullcone" { print $1; exit }')
  b=$(reg_list | awk -F'|' '$2 == "portrestricted" { print $1; exit }')
  [[ -n $a && -n $b ]] || { fail "场景需要 fullcone + portrestricted 各一个（两种锥形 NAT）"; return 1; }

  start_pair_with_relay "$a" "$b" || return 1
  wait_pair_mutual_view "$a" "$b" || return 1
  peer_addresses "$a" "$b"
  local b4 b6 a4 a6
  b4=$(peer_field "$a" ipv4); b6=$(peer_field "$a" ipv6)
  a4=$(peer_field "$b" ipv4); a6=$(peer_field "$b" ipv6)

  note "断言 1：双向 IPv4 / ULA IPv6 Node Address ping"
  ping_assert "$a" "$b4" "$a → $b IPv4（${b4}）"
  ping_assert "$b" "$a4" "$b → $a IPv4（${a4}）"
  ping_assert "$a" "$b6" "$a → $b IPv6（${b6}）" -6
  ping_assert "$b" "$a6" "$b → $a IPv6（${a6}）" -6

  note "断言 2：双方 hzd 日志出现 path=direct（打洞升级成功）"
  wait_for_log "$ART_DIR/hz-node-$a.log" "path=direct" "$a 升级 Direct Path" 90 || return 1
  wait_for_log "$ART_DIR/hz-node-$b.log" "path=direct" "$b 升级 Direct Path" 90 || return 1
  # 数据面报告交叉验证（#15）：hz status 的路径不再只能靠日志判断。
  wait_peer_path "$a" direct 30 || return 1
  wait_peer_path "$b" direct 30 || return 1
  local status_out; status_out=$(hz_cli "$a" status)
  if grep -q "Direct Path" <<<"$status_out"; then
    pass "${a}：hz status 对端表出现 Direct Path"
  else
    fail "${a}：hz status 缺少 Direct Path：$(hz_cli "$a" status | tail -2)"
  fi

  note "断言 3：STUN 公网 Endpoint 已发现并上报（锥形静态映射端口）"
  wait_for_log "$ART_DIR/hz-node-$a.log" "stun mapped endpoint discovered" "$a STUN 映射发现" 60 || return 1
  local wan_a ext_a wan_b ext_b
  wan_a="203.0.113.1$(nat_num_of fullcone)"
  wan_b="203.0.113.1$(nat_num_of portrestricted)"
  ext_a=$(reg_field "$a" 5); ext_b=$(reg_field "$b" 5)
  # 日志行带 ANSI 颜色码，直接匹配 "值+空格"（字段值后即消息文本）。
  grep -q "$wan_a:$ext_a$" "$ART_DIR/hz-node-$a.log" \
    && pass "${a}：STUN Endpoint = $wan_a:${ext_a}（静态映射端口）" \
    || fail "${a}：STUN Endpoint 与静态映射不符（期望 $wan_a:${ext_a}）：$(grep 'stun mapped' "$ART_DIR/hz-node-$a.log" | tail -1)"
  grep -q "$wan_b:$ext_b$" "$ART_DIR/hz-node-$b.log" \
    && pass "${b}：STUN Endpoint = $wan_b:${ext_b}（静态映射端口）" \
    || fail "${b}：STUN Endpoint 与静态映射不符（期望 $wan_b:${ext_b}）：$(grep 'stun mapped' "$ART_DIR/hz-node-$b.log" | tail -1)"

  note "断言 4：Coordination Server 不参与打洞信令（coord 日志无 punch 痕迹）"
  local punch_hits
  punch_hits=$(grep -ci punch "$ART_DIR/coord.log" || true)
  if (( punch_hits == 0 )); then
    pass "coord.log 无 punch 字样（打洞信令只走 Relay 通道）"
  else
    fail "coord.log 出现 punch 相关内容 x${punch_hits}"
  fi

  note "断言 5：hzd 仍只持一个 UDP socket（打洞复用）"
  assert_single_udp_socket "$a" "$b"

  unset HZD_NODE_EXTRA
  (( FAILURES == 0 ))
}

# ---------------------------------------------------------------------------
# 套件 symcone（FR-8）：对称 + 端口受限锥形，直连必失败 → 稳定 Relayed Path
# ---------------------------------------------------------------------------
assert_suite_symcone() {
  local a b b4 a4 i flaps
  a=$(reg_list | awk -F'|' '$2 == "symmetric" { print $1; exit }')
  b=$(reg_list | awk -F'|' '$2 == "portrestricted" { print $1; exit }')
  [[ -n $a && -n $b ]] || { fail "场景需要 symmetric + portrestricted 各一个"; return 1; }

  start_pair_with_relay "$a" "$b" || return 1
  wait_pair_mutual_view "$a" "$b" || return 1
  b4=$(peer_field "$a" ipv4); a4=$(peer_field "$b" ipv4)

  note "断言 1：双向 ping（经 Relay）"
  ping_assert "$a" "$b4" "$a → $b IPv4 经 Relay（${b4}）"
  ping_assert "$b" "$a4" "$b → $a IPv4 经 Relay（${a4}）"

  note "断言 2：60s 观察窗内不出现 path=direct（直连失败后稳定走 Relay，不抖动）"
  flaps=0
  for i in $(seq 1 20); do
    sleep 3
    flaps=$(( flaps + $(grep -c "path=direct" "$ART_DIR/hz-node-$a.log" 2>/dev/null || true) \
                    + $(grep -c "path=direct" "$ART_DIR/hz-node-$b.log" 2>/dev/null || true) ))
  done
  if (( flaps == 0 )); then
    pass "60s 内双方均未升级 Direct（对称×端口受限无直连路径）"
  else
    fail "观察窗内出现 path=direct x${flaps}，不应发生"
  fi

  note "断言 3：窗口结束时连通仍在"
  ping_assert "$a" "$b4" "$a → $b 窗口后仍通（${b4}）"

  unset HZD_NODE_EXTRA
  (( FAILURES == 0 ))
}

# ---------------------------------------------------------------------------
# 套件 symsym（FR-8）：双对称 NAT，路径管理自选 Relay（无 HZD_FORCE_RELAY）
# ---------------------------------------------------------------------------
assert_suite_symsym() {
  local a b b4 a4 i flaps
  read -r a b <<<"$(pick_two symmetric)"
  [[ -n $a && -n $b ]] || { fail "场景需要恰好两个 symmetric 节点"; return 1; }

  start_pair_with_relay "$a" "$b" || return 1
  wait_pair_mutual_view "$a" "$b" || return 1
  b4=$(peer_field "$a" ipv4); a4=$(peer_field "$b" ipv4)

  note "断言 1：双向 ping（经 Relay）"
  ping_assert "$a" "$b4" "$a → $b IPv4 经 Relay（${b4}）"
  ping_assert "$b" "$a4" "$b → $a IPv4 经 Relay（${a4}）"

  note "断言 2：60s 观察窗内不出现 path=direct"
  flaps=0
  for i in $(seq 1 20); do
    sleep 3
    flaps=$(( flaps + $(grep -c "path=direct" "$ART_DIR/hz-node-$a.log" 2>/dev/null || true) \
                    + $(grep -c "path=direct" "$ART_DIR/hz-node-$b.log" 2>/dev/null || true) ))
  done
  (( flaps == 0 )) && pass "双对称 NAT 稳定走 Relay" || fail "出现 path=direct x${flaps}，双对称不应直连"

  note "断言 3：窗口结束时连通仍在"
  ping_assert "$a" "$b4" "$a → $b 窗口后仍通（${b4}）"

  unset HZD_NODE_EXTRA
  (( FAILURES == 0 ))
}

# ---------------------------------------------------------------------------
# 套件 v6pair（FR-8）：双方都有全球单播 IPv6，优先 IPv6 Direct Path
# ---------------------------------------------------------------------------
assert_suite_v6pair() {
  local a b b4 b6 a4 a6 a_ns b_ns
  a=$(reg_list | awk -F'|' '$2 == "fullcone" { print $1; exit }')
  b=$(reg_list | awk -F'|' '$2 == "portrestricted" { print $1; exit }')
  [[ -n $a && -n $b ]] || { fail "场景需要 fullcone + portrestricted 各一个（两种锥形 NAT）"; return 1; }
  a_ns=$(node_ns "$a"); b_ns=$(node_ns "$b")

  note "前置：双方 eth0 各有 2001:db8::/32 全球单播地址且互通"
  local a_v6 b_v6
  a_v6=$(ip netns exec "$a_ns" ip -6 addr show dev eth0 scope global | awk '/2001:db8/{print $2; exit}' | cut -d/ -f1)
  b_v6=$(ip netns exec "$b_ns" ip -6 addr show dev eth0 scope global | awk '/2001:db8/{print $2; exit}' | cut -d/ -f1)
  [[ -n $a_v6 && -n $b_v6 ]] || { fail "Node 缺少 v6 地址（a=$a_v6 b=${b_v6}），HZ_WAN_V6 未生效？"; return 1; }
  local probe_rc=1 probe
  for probe in 1 2 3 4 5 6 7 8 9 10; do
    if ip netns exec "$a_ns" ping -6 -c 2 -W 2 "$b_v6" >/dev/null 2>&1; then probe_rc=0; break; fi
    sleep 1
  done
  if (( probe_rc == 0 )); then
    pass "底层 v6 直达（$a_v6 → ${b_v6}，DAD 稳定后第 ${probe} 次探测通过）"
  else
    fail "底层 v6 不通，v6 直连无从谈起"
  fi

  start_pair_with_relay "$a" "$b" || return 1
  wait_pair_mutual_view "$a" "$b" || return 1
  peer_addresses "$a" "$b"
  b4=$(peer_field "$a" ipv4); b6=$(peer_field "$a" ipv6)
  a4=$(peer_field "$b" ipv4); a6=$(peer_field "$b" ipv6)

  note "断言 1：Node Address 双向 ping（v4 与 ULA v6）"
  ping_assert "$a" "$b4" "$a → $b IPv4（${b4}）"
  ping_assert "$b" "$a4" "$b → $a IPv4（${a4}）"
  ping_assert "$a" "$b6" "$a → $b IPv6（${b6}）" -6
  ping_assert "$b" "$a6" "$b → $a IPv6（${a6}）" -6

  note "断言 2：双方选择 IPv6 Direct Path（日志 path=direct 的 endpoint 落在 2001:db8::/32）"
  wait_for_log "$ART_DIR/hz-node-$a.log" "path=direct.*2001:db8" "$a 以 IPv6 直连" 90 || return 1
  wait_for_log "$ART_DIR/hz-node-$b.log" "path=direct.*2001:db8" "$b 以 IPv6 直连" 90 || return 1

  note "断言 3：v4 STUN Endpoint 仍被发现（IPv6 优先不排斥 v4 候选）"
  wait_for_log "$ART_DIR/hz-node-$a.log" "stun mapped endpoint discovered" "$a STUN 映射发现" 60 || return 1

  note "断言 4：hzd 单 UDP socket（v4/v6 双栈共用）"
  assert_single_udp_socket "$a" "$b"

  unset HZD_NODE_EXTRA
  (( FAILURES == 0 ))
}

# ---------------------------------------------------------------------------
# 套件 blockfallback（FR-8）：直连建立后阻断 WG 端口，退回 Relay 且连通不中断
# ---------------------------------------------------------------------------
assert_suite_blockfallback() {
  local a b b4 a4 natnum before_a before_b after_a after_b
  a=$(reg_list | awk -F'|' '$2 == "fullcone" { print $1; exit }')
  b=$(reg_list | awk -F'|' '$2 == "portrestricted" { print $1; exit }')
  [[ -n $a && -n $b ]] || { fail "场景需要 fullcone + portrestricted 各一个（两种锥形 NAT）"; return 1; }

  start_pair_with_relay "$a" "$b" || return 1
  wait_pair_mutual_view "$a" "$b" || return 1
  b4=$(peer_field "$a" ipv4); a4=$(peer_field "$b" ipv4)
  ping_assert "$a" "$b4" "$a → $b IPv4（${b4}）"
  wait_for_log "$ART_DIR/hz-node-$a.log" "path=direct" "$a 升级 Direct Path" 90 || return 1
  wait_for_log "$ART_DIR/hz-node-$b.log" "path=direct" "$b 升级 Direct Path" 90 || return 1

  note "人为阻断：在 $b 的 NAT 上丢弃双向 WG 端口流量（Relay 的 TCP 不受影响）"
  natnum=$(nat_num_of "$(reg_field "$b" 2)")
  ip netns exec "hz-nat$natnum" nft insert rule ip "hz-nat$natnum" filterin udp dport "$HZ_WG_PORT" drop
  ip netns exec "hz-nat$natnum" nft insert rule ip "hz-nat$natnum" filterin udp sport "$HZ_WG_PORT" drop
  pass "已在 hz-nat$natnum 的 forward 链首插入 udp port $HZ_WG_PORT 双向 drop"
  before_a=$(grep -c "path=direct" "$ART_DIR/hz-node-$a.log" || true)
  before_b=$(grep -c "path=direct" "$ART_DIR/hz-node-$b.log" || true)

  note "断言 1：15s 内双方退回 Relay（path=relay）"
  wait_for_log "$ART_DIR/hz-node-$a.log" "path=relay" "$a 退回 Relayed Path" 15 || return 1
  wait_for_log "$ART_DIR/hz-node-$b.log" "path=relay" "$b 退回 Relayed Path" 15 || return 1

  note "断言 2：连通不中断（退回后 ping 恢复应答）"
  ping_assert "$a" "$b4" "$a → $b IPv4 经 Relay 恢复（${b4}）"
  ping_assert "$b" "$a4" "$b → $a IPv4 经 Relay 恢复（${a4}）"

  note "断言 3：退回后 20s 内不再反复升级（阻断期间无 path=direct 增量）"
  sleep 20
  after_a=$(grep -c "path=direct" "$ART_DIR/hz-node-$a.log" || true)
  after_b=$(grep -c "path=direct" "$ART_DIR/hz-node-$b.log" || true)
  if (( after_a == before_a && after_b == before_b )); then
    pass "阻断期间无再次直连（${before_a}/${before_b} 次保持不变）"
  else
    fail "阻断期间出现新的 path=direct（${before_a}→${after_a}，${before_b}→${after_b}）"
  fi

  unset HZD_NODE_EXTRA
  (( FAILURES == 0 ))
}

# ---------------------------------------------------------------------------
# 套件 proxysim（FR-8）：cone-cone + 一端黑洞 TUN，STUN 仍是真实出口、直连结果不变
# ---------------------------------------------------------------------------
assert_suite_proxysim() {
  local a b b4 a4 ns stun_line expected
  a=$(reg_list | awk -F'|' '$2 == "fullcone" { print $1; exit }')
  b=$(reg_list | awk -F'|' '$2 == "portrestricted" { print $1; exit }')
  [[ -n $a && -n $b ]] || { fail "场景需要 fullcone + portrestricted 各一个（两种锥形 NAT）"; return 1; }
  ns=$(node_ns "$a")

  # 黑洞先于 hzd 安装：此后的一切观测（STUN、直连）都在接管默认路由的
  # 第三方 TUN 类网络工具在场时发生。物理默认路由以更高 metric 保留在
  # eth0 上（真实工具不删除物理默认，只是以更优 metric 抢占），
  # SO_BINDTODEVICE 绑定 eth0 的 hzd 外层流量仍可经物理口出去（FR-7）。
  note "PROXY_SIM：$a 先安装接管默认路由的黑洞 TUN，再启动 hzd"
  local gw ipaddr
  ipaddr=$(reg_field "$a" 4); gw="${ipaddr%.*}.1"
  if ip netns exec "$ns" sh -c "
      ip tuntap add dev proxytun mode tun &&
      ip addr add 198.18.0.1/30 dev proxytun &&
      ip link set proxytun up &&
      ip route replace default via ${gw} dev eth0 metric 100 &&
      ip route add default dev proxytun metric 1
    "; then
    local defaults
    defaults=$(ip netns exec "$ns" ip route show default)
    if [[ $defaults == *proxytun* && $defaults == *eth0* ]]; then
      pass "黑洞生效：默认路由由第三方 TUN 以更优 metric 接管，物理默认保留在 eth0（${defaults}）"
    else
      fail "默认路由形态异常：$defaults"
    fi
  else
    fail "第三方 TUN 模拟（proxytun）配置失败"
  fi

  start_pair_with_relay "$a" "$b" || return 1
  wait_pair_mutual_view "$a" "$b" || return 1
  b4=$(peer_field "$a" ipv4); a4=$(peer_field "$b" ipv4)

  note "断言 1：黑洞之下 STUN 仍发现真实出口公网 Endpoint（≠ 198.18.0.1 黑洞地址）"
  wait_for_log "$ART_DIR/hz-node-$a.log" "stun mapped endpoint discovered" "$a STUN 映射发现" 90 || return 1
  expected="203.0.113.1$(nat_num_of fullcone):$(reg_field "$a" 5)"
  if grep -q -- "$expected" "$ART_DIR/hz-node-a.log"; then
    pass "${a}：STUN Endpoint = ${expected}（真实出口，非黑洞地址 198.18.0.1）"
  else
    stun_line=$(grep "stun mapped endpoint discovered" "$ART_DIR/hz-node-a.log" | tail -1)
    fail "${a}：STUN Endpoint 异常（期望 ${expected}）：$stun_line"
  fi

  note "断言 2：黑洞之下仍建立 Direct Path、双向 ping"
  wait_for_log "$ART_DIR/hz-node-$a.log" "path=direct" "$a 升级 Direct Path（黑洞共存）" 90 || return 1
  wait_for_log "$ART_DIR/hz-node-$b.log" "path=direct" "$b 升级 Direct Path（黑洞共存）" 90 || return 1
  ping_assert "$a" "$b4" "$a → $b IPv4（${b4}）"
  ping_assert "$b" "$a4" "$b → $a IPv4（${a4}）"

  unset HZD_NODE_EXTRA
  (( FAILURES == 0 ))
}

# ---------------------------------------------------------------------------
# 套件 policy_dev_db：ticket #13 Policy（FR-10 / ADR-0006 / A1）
# ---------------------------------------------------------------------------
peer_names_of() { # peer_names_of <node>：status json 的对端名列表（逗号分隔、排序）
  node_status_json "$1" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(",".join(sorted(p["name"] for p in (d.get("peers") or []))))'
}

wait_peer_set() { # wait_peer_set <node> <期望对端名逗号串>
  local node="$1" expected="$2" i
  for i in $(seq 1 60); do
    if [[ $(peer_names_of "$node") == "$expected" ]]; then return 0; fi
    sleep 0.5
  done
  fail "${node}：对端视图未在 30s 内变为 [$expected]，实际 [$(peer_names_of "$node")]"
  return 1
}

policy_field() { # policy_field <node> <field>（status json 的 policy 段）
  node_status_json "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["policy"]["'"$2"'"])'
}

tcp_connect() { # tcp_connect <node> <ip> <port> <timeout-secs>：成功打印 OK
  local ns; ns=$(node_ns "$1")
  ip netns exec "$ns" timeout "$4" python3 -c '
import socket, sys
s = socket.socket(); s.settimeout(float(sys.argv[3]))
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
except OSError as e:
    sys.exit(1)
s.sendall(b"ping")
print("OK")
' "$2" "$3" "$4" 2>/dev/null
}

listen_forever() { # listen_forever <node> <port>：ns 内起一个回显式 TCP 监听（后台）
  local ns; ns=$(node_ns "$1")
  ip netns exec "$ns" setsid python3 -c '
import socket, sys
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", int(sys.argv[1]))); srv.listen(8)
while True:
    conn, _ = srv.accept()
    try:
        conn.recv(64); conn.sendall(b"pong")
    finally:
        conn.close()
' "$2" > "$ART_DIR/listener-$1-$2.log" 2>&1 &
}

assert_suite_policy_dev_db() {
  local db="$ART_DIR/coord.db" a b d
  a=$(reg_list | awk -F'|' '$1 == "a" { print $1; exit }')
  b=$(reg_list | awk -F'|' '$1 == "b" { print $1; exit }')
  d=$(reg_list | awk -F'|' '$1 == "d" { print $1; exit }')
  [[ -n $a && -n $b && -n $d ]] || { fail "场景需要 a/b/d 三个节点"; return 1; }

  note "[$d] 签发带 tag:db 的 Auth Key（FR-1：预绑定 Tag）"
  ip netns exec "$WAN_NS" "$BIN_DIR/hz-coord" bootstrap --db "$db" \
    --auth-key-expiry 1d --tag db --json > "$ART_DIR/key-db-tag.json" || { fail "bootstrap tag key 失败"; return 1; }

  note "[a/b/d] 启动 hzd 并注册（a、b 用普通 Key，d 用 tag Key）"
  start_node_daemon "$a" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$a"'.json"))["auth_key"])')" || return 1
  start_node_daemon "$b" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$b"'.json"))["auth_key"])')" || return 1
  start_node_daemon "$d" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-db-tag.json"))["auth_key"])')" || return 1

  note "等待无 Policy 时的全互通（bootstrap 态）"
  wait_peer_set "$a" "hznodeb,hznoded" || return 1
  wait_peer_set "$b" "hznodea,hznoded" || return 1
  wait_peer_set "$d" "hznodea,hznodeb" || return 1
  pass "无 Policy 时三方全互通"

  note "种入 alice(Admin)/bob 身份与 Node 归属（生产路径是交互式登录，此处直写库）"
  python3 - "$db" <<'PY' || { fail "身份种子写入失败"; return 1; }
import sqlite3, sys
db = sqlite3.connect(sys.argv[1], timeout=10)
db.execute("INSERT OR IGNORE INTO users (id, name, is_admin) VALUES ('u-alice', 'alice', 1)")
db.execute("INSERT OR IGNORE INTO users (id, name, is_admin) VALUES ('u-bob', 'bob', 0)")
db.execute("UPDATE nodes SET user_id = 'u-alice' WHERE name = 'hznodea'")
db.execute("UPDATE nodes SET user_id = 'u-bob' WHERE name = 'hznodeb'")
db.commit()
PY

  cat > "$ART_DIR/policy-5432.toml" <<'EOF'
[[group]]
name = "dev"
users = ["alice"]

[[rule]]
from = "group:dev"
to = "tag:db"
ports = [5432]
EOF

  note "[$a] alice（Admin）推送 Policy：group:dev → tag:db:5432"
  if out=$(hz_cli "$a" policy push "$ART_DIR/policy-5432.toml"); then
    pass "Policy 推送成功：$out"
  else
    fail "Policy 推送失败：$out"
    return 1
  fi

  note "断言 1：Network Map 按订阅者过滤（ADR-0006）"
  wait_peer_set "$a" "hznoded" || return 1
  pass "a（dev 成员）的 Map 只剩 db"
  wait_peer_set "$b" "" || return 1
  pass "b（非 dev 成员）的 Map 没有 hznoded（Seam A AC）"
  wait_peer_set "$d" "hznodea" || return 1
  pass "d 的 Map 只剩 a（可见性方向无关）"

  local d4
  d4=$(node_status_json "$a" | python3 -c 'import json,sys; print(json.load(sys.stdin)["peers"][0]["ipv4"])')
  note "d 的 Node Address（a 视角）：$d4"

  # 数据面就绪门槛：对端可见（Map）不等于路径已建立（打洞/握手）。
  # 慢速 runner 上首条连接断言可能落在打洞退避窗口内；等 a 的日志出现
  # 指向 d 的 path=direct 再断言连通性，其余断言口径不变。
  wait_for_log "$ART_DIR/hz-node-a.log" "path=direct.*$(reg_field "$d" 4)" \
    "a 至 d 直连路径就绪" 60 || return 1

  note "断言 2：a → d:5432 可达（目标侧监听走 wg 路径）"
  listen_forever "$d" 5432
  sleep 0.5
  if [[ $(tcp_connect "$a" "$d4" 5432 5) == OK ]]; then
    pass "a → d:5432 连通（dev 成员连 tag:db:5432）"
  else
    fail "a → d:5432 不通"
  fi

  note "断言 3：a → d:22 被目标 Node 入站过滤拒绝（A1）+ 丢弃计数"
  local dropped_before
  dropped_before=$(policy_field "$d" dropped)
  if tcp_connect "$a" "$d4" 22 4; then
    fail "a → d:22 不应连通（Policy 只放行 5432）"
  else
    pass "a → d:22 连接失败（超时/拒绝）"
  fi
  local dropped_after i
  for i in $(seq 1 10); do
    dropped_after=$(policy_field "$d" dropped)
    (( dropped_after > dropped_before )) && break
    sleep 0.5
  done
  if (( dropped_after > dropped_before )); then
    pass "d 的 Policy 丢弃计数增加：$dropped_before → $dropped_after"
  else
    fail "d 的丢弃计数未增加（$dropped_before → ${dropped_after}）"
  fi

  note "断言 4：b → d:5432 不通（b 的 Map 没有 d，无路由/无对端）"
  if tcp_connect "$b" "$d4" 5432 4; then
    fail "b → d:5432 不应连通"
  else
    pass "b → d:5432 连接失败（非成员不可见）"
  fi

  note "断言 5：a ping d 可达（非 TCP/UDP 跟随 Map 可见性）"
  ping_assert "$a" "$d4" "a → d ICMP（${d4}）"

  note "断言 6：第二份 Policy 放行 22 → 5 秒内生效"
  cat > "$ART_DIR/policy-5432-22.toml" <<'EOF'
[[group]]
name = "dev"
users = ["alice"]

[[rule]]
from = "group:dev"
to = "tag:db"
ports = [5432, 22]
EOF
  listen_forever "$d" 22
  sleep 0.5
  if out=$(hz_cli "$a" policy push "$ART_DIR/policy-5432-22.toml"); then
    pass "第二份 Policy 推送成功：$out"
  else
    fail "第二份 Policy 推送失败：$out"
    return 1
  fi
  local push_time connected
  push_time=$(date +%s.%N)
  connected=""
  for i in $(seq 1 50); do
    if [[ $(tcp_connect "$a" "$d4" 22 1) == OK ]]; then connected=yes; break; fi
    sleep 0.1
  done
  local elapsed
  elapsed=$(python3 -c "import sys, time; sys.stdout.write('%.1f' % (time.time() - float(sys.argv[1])))" "$push_time")
  if [[ -n $connected ]]; then
    if python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) < 5.0 else 1)" "$elapsed"; then
      pass "Policy 更新后 ${elapsed}s 内 a → d:22 连通（< 5s AC）"
    else
      fail "a → d:22 最终连通但耗时 ${elapsed}s，超过 5s AC"
    fi
  else
    fail "第二份 Policy 后 a → d:22 仍不通"
  fi

  note "断言 7：校验失败的 Policy 整份被拒绝、现行不变"
  echo 'this is [not toml' > "$ART_DIR/policy-bad.toml"
  if hz_cli "$a" policy push "$ART_DIR/policy-bad.toml" >/dev/null 2>&1; then
    fail "语法错误的 Policy 不应推送成功"
  else
    pass "语法错误的 Policy 被整份拒绝"
  fi
  local policy_out; policy_out=$(hz_cli "$a" policy get)
  if grep -q 'ports = \[5432, 22\]' <<<"$policy_out"; then
    pass "现行 Policy 保持版本 2 内容"
  else
    fail "现行 Policy 内容异常（get 输出：$(hz_cli "$a" policy get 2>&1 | head -4 | tr '\n' ' ')）"
  fi

  note "断言 8：历史版本与回滚"
  if hz_cli "$a" policy rollback 1 >/dev/null 2>&1; then
    pass "回滚到版本 1 成功"
  else
    fail "回滚到版本 1 失败"
  fi
  if wait_peer_set "$a" "hznoded"; then
    pass "回滚后 a 的 Map 仍只含 d（规则同形）"
  else
    fail "回滚后 a 的 Map 异常"
  fi
  if tcp_connect "$a" "$d4" 22 3; then
    fail "回滚到只放行 5432 后 a → d:22 不应连通"
  else
    pass "回滚后 a → d:22 重新被拒（5 秒内生效同一条通道）"
  fi

  note "断言 9：非 Admin 的 Node 不能推送"
  if hz_cli "$b" policy push "$ART_DIR/policy-5432.toml" >/dev/null 2>&1; then
    fail "b（非 Admin）不应能推送 Policy"
  else
    pass "b（非 Admin）推送被拒绝"
  fi
  if hz_cli "$d" policy push "$ART_DIR/policy-5432.toml" >/dev/null 2>&1; then
    fail "d（带 Tag 无归属）不应能推送 Policy"
  else
    pass "d（带 Tag）推送被拒绝（A3）"
  fi

  (( FAILURES == 0 ))
}

# ---------------------------------------------------------------------------
# 套件 ratelimit（FR-9 / issue #15）：双对称 NAT 强制 Relay，限速生效且可观测
# ---------------------------------------------------------------------------
wait_peer_path() { # wait_peer_path <node> <direct|relay> [timeout-secs]
  local node="$1" expected="$2" timeout="${3:-60}" i current
  for i in $(seq 1 $((timeout * 2))); do
    current=$(peer_field "$node" path 2>/dev/null)
    if [[ $current == "$expected" ]]; then
      pass "${node}：hz status 路径=${expected}（数据面报告）"
      return 0
    fi
    sleep 0.5
  done
  fail "${node}：hz status 路径未变为 ${expected}（当前 ${current:-无}）"
  return 1
}

own_node_id() { # own_node_id <node>
  node_status_json "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["node_id"])'
}

mesh_udp_throughput() { # mesh_udp_throughput <sender> <receiver> <dst-v4> <secs> → 输出接收侧 Mbps
  local sender="$1" receiver="$2" dst="$3" secs="$4" sns rns recv_bytes
  sns=$(node_ns "$sender"); rns=$(node_ns "$receiver")
  ip netns exec "$rns" python3 - "$((secs + 3))" > "$ART_DIR/tput-recv.out" <<PY &
import socket, sys, time
window = float(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8_000_000)
s.bind(("0.0.0.0", 9999))
s.settimeout(1.0)
total = 0
deadline = time.time() + window
while time.time() < deadline:
    try:
        data, _ = s.recvfrom(2048)
        total += len(data)
    except socket.timeout:
        pass
print(total)
PY
  sleep 1
  ip netns exec "$sns" python3 - "$dst" "$secs" > /dev/null <<PY
import socket, sys, time
dst, secs = sys.argv[1], float(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8_000_000)
payload = b"z" * 1200  # hz0 MTU 1280：留出 IP+UDP 头，避免分片
deadline = time.time() + secs
while time.time() < deadline:
    s.sendto(payload, (dst, 9999))
PY
  wait
  recv_bytes=$(cat "$ART_DIR/tput-recv.out")
  python3 -c "print(f'{$recv_bytes * 8 / ($secs * 1_000_000):.2f}')"
}

metrics_value() { # metrics_value <metrics-text> <metric-prefix> → 数值（空=缺失）
  local text="$1" prefix="$2"
  grep -F "$prefix" <<<"$text" | tail -1 | awk '{print $2}'
}

assert_suite_ratelimit() {
  local a b b4 a4 out rc tput limit lo hi ida metrics bytes_in dropped sessions
  read -r a b <<<"$(pick_two symmetric)"
  [[ -n $a && -n $b ]] || { fail "场景需要恰好两个 symmetric 节点"; return 1; }

  start_pair_with_relay "$a" "$b" || return 1
  wait_pair_mutual_view "$a" "$b" || return 1
  b4=$(peer_field "$a" ipv4); a4=$(peer_field "$b" ipv4)

  note "断言 0：双向 ping 打热 Relayed Path"
  ping_assert "$a" "$b4" "$a → $b IPv4 经 Relay（${b4}）"
  ping_assert "$b" "$a4" "$b → $a IPv4 经 Relay（${a4}）"

  note "断言 1：hz status 显示每个对端的路径 Relayed Path"
  wait_peer_path "$a" relay || return 1
  wait_peer_path "$b" relay || return 1
  local status_out; status_out=$(hz_cli "$a" status)
  if grep -q "Relayed Path" <<<"$status_out"; then
    pass "${a}：hz status 对端表出现 Relayed Path"
  else
    fail "${a}：hz status 缺少 Relayed Path：$(hz_cli "$a" status | tail -2)"
  fi

  note "断言 2：hz ping 显示往返时延与所走路径"
  rc=0; out=$(hz_cli "$a" ping "hznode$b") || rc=$?
  if [[ $rc -eq 0 && $out == *"往返"* && $out == *"Relayed Path"* ]]; then
    pass "$a → ${b}：$out"
  else
    fail "hz ping 输出异常（rc=${rc}）：$out"
  fi
  rc=0; out=$(hz_cli "$b" ping "hznode$a") || rc=$?
  if [[ $rc -eq 0 && $out == *"往返"* && $out == *"Relayed Path"* ]]; then
    pass "$b → ${a}：$out"
  else
    fail "hz ping 输出异常（rc=${rc}）：$out"
  fi

  note "断言 3：单个 Node 经 Relay 的吞吐不超过配置上限"
  limit=${HZ_RELAY_RATE_MBPS:-2}
  tput=$(mesh_udp_throughput "$a" "$b" "$b4" 10)
  lo=$(python3 -c "print(f'{$limit * 0.5:.2f}')")
  hi=$(python3 -c "print(f'{$limit * 1.2:.2f}')")
  note "实测 ${tput} Mbps（限速 ${limit} Mbps，判据 ${lo}–${hi}；差额=WireGuard 封装开销+令牌桶 1s 突发）"
  if python3 -c "import sys; sys.exit(0 if $lo <= $tput <= $hi else 1)"; then
    pass "$a → $b 经 Relay 吞吐 ${tput} Mbps ≤ ${limit} Mbps×1.2 且 ≥ ×0.5"
  else
    fail "吞吐 ${tput} Mbps 越界（限速 ${limit} Mbps，判据 ${lo}–${hi}）"
  fi

  note "断言 4：Relay /metrics 可抓取按 Node 流量、丢弃与在线会话"
  ida=$(own_node_id "$a")
  metrics=$(ip netns exec "$WAN_NS" curl -s http://127.0.0.1:9101/metrics)
  bytes_in=$(metrics_value "$metrics" "hz_relay_node_bytes_total{direction=\"in\",node_id=\"$ida\"}")
  dropped=$(metrics_value "$metrics" "hz_relay_dropped_bytes_total{node_id=\"$ida\"}")
  sessions=$(metrics_value "$metrics" "hz_relay_sessions")
  if [[ -n $bytes_in && $bytes_in -gt 0 ]]; then
    pass "hz_relay_node_bytes_total{in}[$ida] = $bytes_in"
  else
    fail "缺少 $ida 的 in 字节计数：$bytes_in"
  fi
  if [[ -n $dropped && $dropped -gt 0 ]]; then
    pass "hz_relay_dropped_bytes_total[$ida] = ${dropped}（限速丢帧在案）"
  else
    fail "丢弃计数缺失或为零：${dropped}（限速 2 Mbps 下超限帧应有丢弃）"
  fi
  if [[ $sessions == 2 ]]; then
    pass "hz_relay_sessions = 2"
  else
    fail "hz_relay_sessions = ${sessions:-缺失}（应为 2）"
  fi

  note "断言 5：Coordination Server /metrics 可抓取在线数与打洞计数"
  local coord_metrics online attempts ratio i
  attempts=""
  for i in $(seq 1 90); do
    coord_metrics=$(ip netns exec "$WAN_NS" curl -s http://127.0.0.1:9100/metrics)
    attempts=$(metrics_value "$coord_metrics" "hz_coord_punch_attempts_total")
    [[ -n $attempts && $attempts -gt 0 ]] && break
    sleep 1
  done
  online=$(metrics_value "$coord_metrics" "hz_coord_online_nodes")
  ratio=$(metrics_value "$coord_metrics" "hz_coord_punch_success_ratio")
  if [[ $online == 2 ]]; then
    pass "hz_coord_online_nodes = 2"
  else
    fail "hz_coord_online_nodes = ${online:-缺失}（应为 2）"
  fi
  if [[ -n $attempts && $attempts -gt 0 ]]; then
    pass "hz_coord_punch_attempts_total = ${attempts}（双对称打洞在案）"
  else
    fail "hz_coord_punch_attempts_total = ${attempts:-缺失}（应为 >0）"
  fi
  [[ -n $ratio ]] && pass "hz_coord_punch_success_ratio = $ratio" || fail "缺少 hz_coord_punch_success_ratio"

  unset HZD_NODE_EXTRA
  (( FAILURES == 0 ))
}

# ---------------------------------------------------------------------------
# 套件 admin_revoke：ticket #12 Admin 远程管理（FR-11 / A3）
# ---------------------------------------------------------------------------
node_field_of() { # node_field_of <operator-node> <target-name> <field>：node list json 里按名字取字段
  hz_cli "$1" node list --json 2>/dev/null | python3 -c '
import json, sys
nodes = json.load(sys.stdin)
node = next(n for n in nodes if n["name"] == sys.argv[1])
print(node[sys.argv[2]])' "$2" "$3"
}

dns_a_record() { # dns_a_record <node> <fqdn>：本地 DNS 应答的 A 记录（手写 UDP 查询）
  local ns; ns=$(node_ns "$1")
  ip netns exec "$ns" timeout 5 python3 - "$2" <<'PY'
import socket, struct, sys
labels = sys.argv[1].split(".")
q = b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00"
msg = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(msg, ("100.96.0.53", 53))
data, _ = s.recvfrom(512)
head = struct.unpack(">HHHHHH", data[:12])
assert head[3] >= 1, f"应答不含 Answer 区：{head}"
# hzd 应答器把问题名原样（非压缩指针）复写在 Answer 区：单条 A 记录的
# RDATA 就是报文末 4 字节。
print(socket.inet_ntoa(data[-4:]))
PY
}

dns_query() { # dns_query <node> <fqdn> <A|AAAA>：输出 IP 字面值 / RCODE:<n> / TIMEOUT
  local ns; ns=$(node_ns "$1")
  local qtype=1
  [[ "$3" == "AAAA" ]] && qtype=28
  ip netns exec "$ns" timeout 5 python3 - "$2" "$qtype" <<'PY'
import socket, struct, sys
fqdn, qtype = sys.argv[1], int(sys.argv[2])
labels = fqdn.split(".")
q = b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00"
msg = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    s.sendto(msg, ("100.96.0.53", 53))
    data, _ = s.recvfrom(512)
except OSError as error:
    print(f"TIMEOUT({error})"); sys.exit(0)
head = struct.unpack(">HHHHHH", data[:12])
rcode = head[1] & 0xF
if rcode != 0 or head[3] < 1:
    print(f"RCODE:{rcode}"); sys.exit(0)
if qtype == 1:
    print(socket.inet_ntoa(data[-4:]))
else:
    print(socket.inet_ntop(socket.AF_INET6, data[-16:]))
PY
}

assert_suite_dns() {
  local a b b4 b6 answer
  a=$(reg_list | awk -F'|' '$2 == "lan" { print $1; exit }')
  b=$(reg_list | awk -F'|' '$2 == "lan" && $1 != "'"$a"'" { print $1; exit }')
  [[ -n $a && -n $b ]] || { fail "场景需要恰好两个 lan 节点"; return 1; }

  note "[$a/$b] 启动 hzd 并注册"
  start_node_daemon "$a" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$a"'.json"))["auth_key"])')" || return 1
  start_node_daemon "$b" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$b"'.json"))["auth_key"])')" || return 1

  note "等待双方的 Network Map 互见"
  if wait_for_peer "$a" "$b" && wait_for_peer "$b" "$a"; then
    pass "双方 Network Map 互见（DNS 应答的数据源就绪）"
  else
    fail "Network Map 未在 90s 内互通"
    return 1
  fi

  b4=$(peer_field "$a" ipv4)
  b6=$(peer_field "$a" ipv6)
  note "断言 1：本地应答返回 Map 里的字面地址（A 与 AAAA）"
  answer=$(dns_query "$a" "hznode${b}.hznet.internal" A)
  if [[ "$answer" == "$b4" ]]; then
    pass "hznode${b}.hznet.internal A → ${answer}（与 Map 字面一致）"
  else
    fail "A 应答 ${answer}，期望 ${b4}"
  fi
  answer=$(dns_query "$a" "hznode${b}.hznet.internal" AAAA)
  if [[ "$answer" == "$b6" ]]; then
    pass "hznode${b}.hznet.internal AAAA → ${answer}（与 Map 字面一致）"
  else
    fail "AAAA 应答 ${answer}，期望 ${b6}"
  fi

  note "断言 2：非 HzNet 域名 REFUSED（不递归、不越权应答）"
  answer=$(dns_query "$a" "github.com" A)
  if [[ "$answer" == "RCODE:5" ]]; then
    pass "github.com → REFUSED"
  else
    fail "github.com 应答 ${answer}，期望 RCODE:5"
  fi

  note "断言 3：hzd 停止后 53 口死寂，重启后应答恢复"
  # 按 netns 作用域取该节点的全部进程再杀 hzd（ip netns pids 天然限定在本
  # 节点，免去 pgrep 全局匹配加 /proc/environ 前缀过滤的脆弱组合）。
  local pid
  for pid in $(ip netns pids "hz-node-${a}"); do
    if tr '\0' '\n' < "/proc/${pid}/cmdline" 2>/dev/null | grep -q '/hzd$'; then
      kill "$pid"
    fi
  done
  sleep 1
  answer=$(dns_query "$a" "hznode${b}.hznet.internal" A)
  if [[ "$answer" == TIMEOUT* ]]; then
    pass "hzd 停止后 ${a} 的 53 口不再应答（${answer}）"
  else
    fail "hzd 停止后仍应答：${answer}"
  fi
  # SIGTERM 不触发 hzd 的 Drop 守卫，UDS 文件残留会让重启后的就绪探测命中死
  # socket——显式清掉再拉起。
  rm -f "$ART_DIR/hzd-${a}.sock"
  start_node_daemon "$a" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$a"'.json"))["auth_key"])')" || return 1
  local i
  for i in $(seq 1 30); do
    answer=$(dns_query "$a" "hznode${b}.hznet.internal" A)
    [[ "$answer" == "$b4" ]] && break
    sleep 1
  done
  if [[ "$answer" == "$b4" ]]; then
    pass "hzd 重启后应答恢复：hznode${b}.hznet.internal A → ${answer}"
  else
    fail "重启后未恢复：${answer}，期望 ${b4}"
    return 1
  fi

  unset HZD_NODE_EXTRA
  (( FAILURES == 0 ))
}

assert_suite_admin_revoke() {
  local db="$ART_DIR/coord.db" a b d b4 d_id out rc start elapsed
  a=$(reg_list | awk -F'|' '$1 == "a" { print $1; exit }')
  b=$(reg_list | awk -F'|' '$1 == "b" { print $1; exit }')
  d=$(reg_list | awk -F'|' '$1 == "d" { print $1; exit }')
  [[ -n $a && -n $b && -n $d ]] || { fail "场景需要 a/b/d 三个节点"; return 1; }

  note "[$d] 签发带 tag:db 的 Auth Key 并种入 Admin alice（bootstrap --admin，无需 Kanidm）"
  ip netns exec "$WAN_NS" "$BIN_DIR/hz-coord" bootstrap --db "$db" \
    --auth-key-expiry 1d --tag db --admin alice --json > "$ART_DIR/key-db-tag.json" \
    || { fail "bootstrap --admin 失败"; return 1; }
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["admin"]=="alice"' "$ART_DIR/key-db-tag.json" \
    && pass "bootstrap --admin alice 落库成功" || fail "bootstrap 应答缺少 admin 字段"

  note "[a/b/d] 启动 hzd 并注册（a、b 用普通 Key，d 用 tag Key）"
  start_node_daemon "$a" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$a"'.json"))["auth_key"])')" || return 1
  start_node_daemon "$b" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-'"$b"'.json"))["auth_key"])')" || return 1
  start_node_daemon "$d" "$(python3 -c 'import json;print(json.load(open("'"$ART_DIR"'/key-db-tag.json"))["auth_key"])')" || return 1

  note "等待无 Policy 时的三方全互通"
  wait_peer_set "$a" "hznodeb,hznoded" || return 1
  wait_peer_set "$b" "hznodea,hznoded" || return 1
  wait_peer_set "$d" "hznodea,hznodeb" || return 1
  pass "三方 Network Map 互见"

  note "种入 bob（普通 User）与 Node 归属（生产路径是交互式登录，此处直写库）"
  python3 - "$db" <<'PY' || { fail "身份种子写入失败"; return 1; }
import sqlite3, sys
db = sqlite3.connect(sys.argv[1], timeout=10)
db.execute("INSERT OR IGNORE INTO users (id, name, is_admin) VALUES ('u-bob', 'bob', 0)")
db.execute("UPDATE nodes SET user_id = (SELECT id FROM users WHERE name = 'alice') WHERE name = 'hznodea'")
db.execute("UPDATE nodes SET user_id = (SELECT id FROM users WHERE name = 'bob') WHERE name = 'hznodeb'")
db.commit()
PY

  note "断言 1：alice 名下的 a 可签发 Auth Key（FR-11 AC）"
  if out=$(hz_cli "$a" authkey create --expiry 7d 2>&1); then
    if [[ $out == *"仅此一次显示"* && $out == *"Key ID："* ]]; then
      pass "a：hz authkey create 成功并提示仅此一次显示"
    else
      fail "a：签发输出形态异常：$out"
    fi
  else
    fail "a：hz authkey create 失败：$out"
    return 1
  fi

  note "断言 2/3：普通 User 与带 Tag 的 Node 签发被拒"
  rc=0; out=$(hz_cli "$b" authkey create --expiry 7d 2>&1) || rc=$?
  if (( rc != 0 )) && [[ $out == *"需要 Admin 权限"* ]]; then
    pass "b（普通 User）：签发被拒（需要 Admin 权限）"
  else
    fail "b：签发应被拒（rc=${rc}）：$out"
  fi
  rc=0; out=$(hz_cli "$d" authkey create --expiry 7d 2>&1) || rc=$?
  if (( rc != 0 )) && [[ $out == *"带 Tag"* ]]; then
    pass "d（带 Tag 的 Node）：管理操作被拒"
  else
    fail "d：签发应被拒（rc=${rc}）：$out"
  fi

  note "断言 4：hz node list 的可见范围（Admin 全部 / User 自己名下）"
  local listed
  listed=$(hz_cli "$a" node list --json | python3 -c 'import json,sys; print(",".join(sorted(n["name"] for n in json.load(sys.stdin))))')
  if [[ $listed == "hznodea,hznodeb,hznoded" ]]; then
    pass "a（Admin）：列表包含全部 3 个 Node"
  else
    fail "a（Admin）：列表异常：$listed"
  fi
  listed=$(hz_cli "$b" node list --json | python3 -c 'import json,sys; print(",".join(sorted(n["name"] for n in json.load(sys.stdin))))')
  if [[ $listed == "hznodeb" ]]; then
    pass "b（普通 User）：列表只有自己名下的 hznodeb"
  else
    fail "b（普通 User）：列表异常：$listed"
  fi
  b4=$(node_field_of "$a" hznodeb ipv4)
  d_id=$(node_field_of "$a" hznoded node_id)
  note "b 的 Node Address（a 视角）：$b4；d 的 node id：$d_id"

  note "断言 5：a 吊销 b → 5 秒内 b 从 a/d 的 Map 消失、无法通信、b 显示已吊销"
  start=$(python3 -c 'import time; print(time.time())')
  if ! out=$(hz_cli "$a" node revoke "$(node_field_of "$a" hznodeb node_id)" 2>&1); then
    fail "a：hz node revoke 失败：$out"
    return 1
  fi
  pass "a：hz node revoke 执行成功"
  if wait_peer_set "$a" "hznoded" && wait_peer_set "$d" "hznodea"; then
    elapsed=$(python3 -c "import sys, time; sys.stdout.write('%.1f' % (time.time() - float(sys.argv[1])))" "$start")
    if python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) < 5.0 else 1)" "$elapsed"; then
      pass "吊销后 ${elapsed}s 内 a 与 d 的 Map 都不再有 hznodeb（< 5s AC）"
    else
      fail "吊销后 ${elapsed}s 才从 Map 消失，超过 5 秒 AC"
    fi
  else
    fail "吊销后 a/d 的对端视图未收敛"
    return 1
  fi
  if ip netns exec "$(node_ns "$a")" ping -c 3 -W 2 "$b4" > /dev/null 2>&1; then
    fail "a → b（${b4}）不应再 ping 通"
  else
    pass "a → b（${b4}）ICMP 不通（Seam A）"
  fi
  rc=0; out=$(hz_cli "$a" ping hznodeb 2>&1) || rc=$?
  if (( rc != 0 )) && [[ $out == *"找不到对端"* ]]; then
    pass "a：hz ping hznodeb 找不到对端"
  else
    fail "a：hz ping hznodeb 应失败（rc=${rc}）：$out"
  fi
  local i revoked_seen=""
  for i in $(seq 1 20); do
    local revoke_out; revoke_out=$(hz_cli "$b" status 2>/dev/null)
    if grep -q "已吊销" <<<"$revoke_out"; then revoked_seen=yes; break; fi
    sleep 0.5
  done
  if [[ -n $revoked_seen ]]; then
    pass "b：hz status 显示已吊销"
  else
    fail "b：hz status 未显示已吊销（实际：$(hz_cli "$b" status | head -2 | tr '\n' ' ')）"
  fi

  note "断言 6：改名冲突拒绝（Node Name 已存在）"
  rc=0; out=$(hz_cli "$a" node rename "$d_id" hznodea 2>&1) || rc=$?
  if (( rc != 0 )) && [[ $out == *"Node Name 已存在"* ]]; then
    pass "改名到已存在的名字被拒：$out"
  else
    fail "改名冲突应被拒（rc=${rc}）：$out"
  fi

  note "断言 7：改成新名 → 对端 Map 与本地 DNS 应答跟随"
  if out=$(hz_cli "$a" node rename "$d_id" hznoded2 2>&1); then
    pass "改名成功：$out"
  else
    fail "改名失败：$out"
    return 1
  fi
  start=$(python3 -c 'import time; print(time.time())')
  if wait_peer_set "$a" "hznoded2"; then
    elapsed=$(python3 -c "import sys, time; sys.stdout.write('%.1f' % (time.time() - float(sys.argv[1])))" "$start")
    if python3 -c "import sys; sys.exit(0 if float(sys.argv[1]) < 5.0 else 1)" "$elapsed"; then
      pass "改名后 ${elapsed}s 内 a 的 Map 显示新名（< 5s）"
    else
      fail "改名后 ${elapsed}s 才生效，超过 5 秒"
    fi
  else
    fail "a 的 Map 未跟随新名 hznoded2"
    return 1
  fi
  local d4 dns
  d4=$(node_field_of "$a" hznoded2 ipv4)
  dns=$(dns_a_record "$a" "hznoded2.hznet.internal")
  if [[ $dns == "$d4" ]]; then
    pass "本地 DNS 应答跟随新名：hznoded2.hznet.internal → $dns"
  else
    fail "DNS 应答异常：hznoded2.hznet.internal → ${dns:-无应答}，期望 $d4"
  fi
  (( FAILURES == 0 ))
}

# 套件 netchange（FR-8 / issue #9）：直连建立后把一个 Node 搬到另一个 NAT
# （新出口 IP + 网卡改名），断言旧路径确实断开、30 秒内恢复连通（计时打印）、
# STUN Endpoint 更换、之后再次升级 Direct Path。
# ---------------------------------------------------------------------------
last_stun_endpoint() { # last_stun_endpoint <node>：日志里最近一次 STUN 映射（ip:port）
  grep 'stun mapped endpoint discovered' "$ART_DIR/hz-node-$1.log" 2>/dev/null \
    | tail -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$'
}

wait_new_direct_log() { # wait_new_direct_log <node> <已有条数> [timeout-secs]：等 path=direct 条数增长
  local node="$1" before="$2" timeout="${3:-60}" i now
  for i in $(seq 1 $((timeout * 2))); do
    now=$(grep -c "path=direct" "$ART_DIR/hz-node-$node.log" 2>/dev/null || true)
    if (( now > before )); then
      pass "${node}：换网后再次出现 path=direct（第 ${now} 条）"
      return 0
    fi
    sleep 0.5
  done
  fail "${node}：${timeout}s 内未见新的 path=direct（仍 ${now:-0} 条）"
  return 1
}

assert_suite_netchange() {
  local a b b4 a4 old_ext new_ext t0 measured i now direct_a direct_b
  a=$(reg_list | awk -F'|' '$2 == "fullcone" { print $1; exit }')
  b=$(reg_list | awk -F'|' '$2 == "portrestricted" { print $1; exit }')
  [[ -n $a && -n $b ]] || { fail "场景需要 fullcone + portrestricted 各一个"; return 1; }

  start_pair_with_relay "$a" "$b" || return 1
  wait_pair_mutual_view "$a" "$b" || return 1
  b4=$(peer_field "$a" ipv4); a4=$(peer_field "$b" ipv4)

  note "断言 1：换网前双向 ping 且已建立 Direct Path"
  ping_assert "$a" "$b4" "$a → $b IPv4（${b4}）"
  ping_assert "$b" "$a4" "$b → $a IPv4（${a4}）"
  wait_for_log "$ART_DIR/hz-node-$a.log" "path=direct" "$a 升级 Direct Path" 90 || return 1
  wait_for_log "$ART_DIR/hz-node-$b.log" "path=direct" "$b 升级 Direct Path" 90 || return 1
  wait_peer_path "$a" direct 30 || return 1
  old_ext=$(last_stun_endpoint "$a")
  [[ $old_ext == 203.0.113.11:* ]] || { fail "$a 换网前 STUN Endpoint 异常：${old_ext:-无}"; return 1; }
  pass "$a 换网前 STUN Endpoint = ${old_ext}（NAT1 出口）"

  note "断言 2：更换 $a 的上游出口（NAT 换 WAN IP + 新静态映射 + 换网卡与新内网地址，模拟换 Wi-Fi）"
  # path=direct 基线在搬移前取：恢复可能快过后续断言的簿记，事后取会漏计。
  direct_a=$(grep -c "path=direct" "$ART_DIR/hz-node-$a.log" || true)
  direct_b=$(grep -c "path=direct" "$ART_DIR/hz-node-$b.log" || true)
  t0=$(date +%s)
  new_ext=$(HZ_TOPO_STATE_DIR="$STATE_DIR" HZ_TOPO_WG_PORT="$HZ_WG_PORT" \
    bash "$TOPO_DIR/netmove.sh" "$a") \
    || { fail "netmove 执行失败"; return 1; }
  [[ $new_ext == 203.0.113.21:40211 ]] || { fail "netmove 返回的新 Endpoint 异常：$new_ext"; return 1; }
  pass "$a 上游已更换，新静态映射 $new_ext"

  note "断言 3：负控——搬移后旧路径确实断开（重绑生效前 ping 不通）"
  if ip netns exec "$(node_ns "$a")" ping -c 1 -W 1 "$b4" >"$ART_DIR/negctl.out" 2>&1; then
    fail "负控失败：搬移后立即 ping 即通（旧路径未真正断开，测试证明不了恢复）"
  else
    pass "负控：搬移后 1s 探测窗口内 $a → $b 不通"
  fi

  note "断言 4：30 秒内恢复与对端连通（Seam A，从搬移完成起计时）"
  measured=0
  while (( $(date +%s) - t0 < 30 )); do
    if ip netns exec "$(node_ns "$a")" ping -c 1 -W 1 "$b4" >/dev/null 2>&1; then
      measured=$(( $(date +%s) - t0 ))
      break
    fi
  done
  if (( measured > 0 )); then
    pass "$a → $b 连通恢复，实测 ${measured}s（≤30s，AC）"
  else
    fail "30s 内未恢复连通（AC 不满足，现场见 forensics）"
  fi
  ping_assert "$b" "$a4" "$b → $a 恢复后双向（${a4}）"

  note "断言 5：恢复后 a 的 STUN Endpoint 已更换为新 NAT 出口"
  wait_for_log "$ART_DIR/hz-node-$a.log" "$new_ext" "$a 新 STUN Endpoint $new_ext" 30 || return 1
  now=$(last_stun_endpoint "$a")
  if [[ $now == "$new_ext" && $now != "$old_ext" ]]; then
    pass "$a STUN Endpoint $old_ext → ${now}（出口 IP 已更换）"
  else
    fail "$a 最近 STUN Endpoint = ${now:-无}（期望 ${new_ext}，旧值 ${old_ext}）"
  fi

  note "断言 6：条件允许时再次升级 Direct Path（≤60s）"
  # a 侧确定性经历 relay→direct 轮回（恢复序列作废直连记账后重新升级，日志可数）；
  # b 侧可能全程未掉出 Direct（direct_rx 新鲜度未超窗，对端直连流量无缝续上），
  # 以数据面报告的路径形态为准。
  wait_new_direct_log "$a" "$direct_a" 60 || return 1
  wait_peer_path "$a" direct 30 || return 1
  wait_peer_path "$b" direct 30 || return 1

  note "断言 7：换网重绑后 hzd 仍只持一个 UDP socket"
  assert_single_udp_socket "$a" "$b"

  note "实测：连通恢复 ${measured}s（上限 30s；构成=去抖 1s+重绑+STUN+上报+重拨）"
  unset HZD_NODE_EXTRA
  (( FAILURES == 0 ))
}
