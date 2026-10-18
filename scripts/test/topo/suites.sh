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
  ip netns exec "$ns" test -S "$ART_DIR/hzd-$name.sock" || { fail "$name：hzd socket 未出现"; return 1; }
  if hz_cli "$name" up --auth-key "$key" >/dev/null 2>&1; then
    pass "$name：hz up --auth-key 注册成功"
  else
    fail "$name：注册失败（见 $ART_DIR/hz-node-$name.log）"
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
      pass "$label（$(grep "$pattern" "$file" | tail -1 | cut -c1-160)）"
      return 0
    fi
    sleep 0.5
  done
  fail "$label：${timeout}s 内未在 $(basename "$file") 见到 /$pattern/"
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
    count=$(ip netns exec "$ns" sh -c "ss -u -a -p 2>/dev/null | grep -c 'hzd' || true")
    if [[ $count == 1 ]]; then
      pass "$node：hzd 恰好 1 个 UDP socket（WireGuard/打洞/STUN 共用，ADR-0002）"
    else
      fail "$node：hzd UDP socket 数量为 ${count}（应为 1）"
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
        pass "黑洞生效：未绑定流量到 $b_lan_ip 已被第三方 TUN 吞下（$blackhole）"
      else
        fail "黑洞未生效，共存场景不成立：$blackhole"
      fi
    else
      fail "第三方 TUN 模拟（proxytun）配置失败"
    fi
    local estab
    estab=$(ip netns exec "$ns" sh -c "ss -t -n -p 2>/dev/null | grep hzd | grep -c ESTAB || true")
    if (( estab >= 1 )); then
      pass "$a：黑洞之下 hzd 与 Coordination Server 的 TCP 连接仍存活（ESTAB x${estab}）"
    else
      fail "$a：hzd 到 Coordination Server 的 TCP 连接丢失"
    fi
    if hz_cli "$a" status >/dev/null 2>&1; then
      pass "$a：hz status 经本地 IPC 正常返回"
    else
      fail "$a：hz status 失败"
    fi
  fi

  note "断言 1：双向 IPv4 Node Address ping"
  ping_assert "$a" "$b4" "$a → $b IPv4（$b4）"
  ping_assert "$b" "$a4" "$b → $a IPv4（$a4）"

  note "断言 2：双向 ULA IPv6 Node Address ping"
  ping_assert "$a" "$b6" "$a → $b IPv6（$b6）" -6
  ping_assert "$b" "$a6" "$b → $a IPv6（$a6）" -6

  note "断言 3：hz0 只接管 HzNet 段（100.100.2.136 不入隧道）"
  local node ns route hz_route
  for node in "$a" "$b"; do
    ns=$(node_ns "$node")
    route=$(ip netns exec "$ns" ip route get 100.100.2.136 2>/dev/null | head -1)
    if [[ $route != *hz0* ]]; then
      pass "$node：100.100.2.136 不经 hz0（$route）"
    else
      fail "$node：100.100.2.136 被路由进 hz0：$route"
    fi
    hz_route=$(ip netns exec "$ns" ip route show dev hz0 2>/dev/null)
    if [[ $hz_route == *"100.96.0.0/16"* && $hz_route != *"100.64.0.0/10"* ]]; then
      pass "$node：hz0 仅接管 100.96.0.0/16（$hz_route）"
    else
      fail "$node：hz0 路由异常：$hz_route"
    fi
  done

  note "断言 4：hzd 仅持有唯一 UDP socket（WireGuard 与打洞共用，ADR-0002）"
  for node in "$a" "$b"; do
    ns=$(node_ns "$node")
    count=$(ip netns exec "$ns" sh -c "ss -u -a -p 2>/dev/null | grep -c 'hzd' || true")
    if [[ $count == 1 ]]; then
      pass "$node：hzd 恰好 1 个 UDP socket"
    else
      fail "$node：hzd UDP socket 数量为 ${count}（应为 1）"
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

unsolicited_listener() { # unsolicited_listener <node>：监听 $HZ_WG_PORT，输出 RECV 或 TIMEOUT
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
    out=$(nat_probe "$name") || { fail "$name：反射器探测无应答"; continue; }
    pa=${out% *}; pb=${out#* }
    case "$att" in
      fullcone)
        [[ $pa == "$extport" && $pb == "$extport" ]] \
          && pass "$name：完全锥形——两个目标看到同一外端口 ${pa}（= 静态映射 $extport）" \
          || fail "$name：完全锥形映射不稳定：$pa/$pb ≠ $extport"
        ;;
      portrestricted)
        [[ $pa == "$extport" && $pb == "$extport" ]] \
          && pass "$name：端口受限——映射与目标无关（${pa} = $extport）" \
          || fail "$name：端口受限映射不稳定：$pa/$pb ≠ $extport"
        ;;
      symmetric)
        [[ $pa != "$pb" ]] \
          && pass "$name：对称型——两个目标看到不同外端口（$pa ≠ $pb）" \
          || fail "$name：对称型未表现出按流变化：$pa == $pb"
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
          && pass "$name：完全锥形——任意第三方入站直达 Node（$out）" \
          || fail "$name：完全锥形应放行任意入站，实际：$out"
        ;;
      portrestricted|symmetric)
        [[ $out == TIMEOUT ]] \
          && pass "$name：$att——未见目标之外的入站被丢弃" \
          || fail "$name：$att 不应放行第三方入站，实际：$out"
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
  ping_assert "$a" "$b4" "$a → $b IPv4 经 Relay（$b4）"
  ping_assert "$b" "$a4" "$b → $a IPv4 经 Relay（$a4）"

  note "断言 2：经 Relay 的双向 ULA IPv6 ping（WG 加密任意 IP，中继不改路径语义）"
  ping_assert "$a" "$b6" "$a → $b IPv6 经 Relay（$b6）" -6
  ping_assert "$b" "$a6" "$b → $a IPv6 经 Relay（$a6）" -6

  note "断言 3：路径确实经过 Relay（双方各持一条到 $RELAY_PORT 的 ESTAB，会话各开一次）"
  for node in "$a" "$b"; do
    ns=$(node_ns "$node")
    estab=$(ip netns exec "$ns" sh -c "ss -t -n -p 2>/dev/null | grep hzd | grep -c ':$RELAY_PORT' || true")
    if (( estab >= 1 )); then
      pass "$node：hzd 与 Relay 的 TLS 连接存活（ESTAB x${estab}）"
    else
      fail "$node：hzd 到 Relay 的 TLS 连接缺失"
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
    fail "未注册身份应被拒绝（rc=$probe_rc）：$probe_out"
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
  ping_assert "$a" "$b4" "$a → $b IPv4（$b4）"
  ping_assert "$b" "$a4" "$b → $a IPv4（$a4）"
  ping_assert "$a" "$b6" "$a → $b IPv6（$b6）" -6
  ping_assert "$b" "$a6" "$b → $a IPv6（$a6）" -6

  note "断言 2：双方 hzd 日志出现 path=direct（打洞升级成功）"
  wait_for_log "$ART_DIR/hz-node-$a.log" "path=direct" "$a 升级 Direct Path" 90 || return 1
  wait_for_log "$ART_DIR/hz-node-$b.log" "path=direct" "$b 升级 Direct Path" 90 || return 1

  note "断言 3：STUN 公网 Endpoint 已发现并上报（锥形静态映射端口）"
  wait_for_log "$ART_DIR/hz-node-$a.log" "stun mapped endpoint discovered" "$a STUN 映射发现" 60 || return 1
  local wan_a ext_a wan_b ext_b
  wan_a="203.0.113.1$(nat_num_of fullcone)"
  wan_b="203.0.113.1$(nat_num_of portrestricted)"
  ext_a=$(reg_field "$a" 5); ext_b=$(reg_field "$b" 5)
  # 日志行带 ANSI 颜色码，直接匹配 "值+空格"（字段值后即消息文本）。
  grep -q "$wan_a:$ext_a$" "$ART_DIR/hz-node-$a.log" \
    && pass "$a：STUN Endpoint = $wan_a:$ext_a（静态映射端口）" \
    || fail "$a：STUN Endpoint 与静态映射不符（期望 $wan_a:$ext_a）：$(grep 'stun mapped' "$ART_DIR/hz-node-$a.log" | tail -1)"
  grep -q "$wan_b:$ext_b$" "$ART_DIR/hz-node-$b.log" \
    && pass "$b：STUN Endpoint = $wan_b:$ext_b（静态映射端口）" \
    || fail "$b：STUN Endpoint 与静态映射不符（期望 $wan_b:$ext_b）：$(grep 'stun mapped' "$ART_DIR/hz-node-$b.log" | tail -1)"

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
  ping_assert "$a" "$b4" "$a → $b IPv4 经 Relay（$b4）"
  ping_assert "$b" "$a4" "$b → $a IPv4 经 Relay（$a4）"

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
  ping_assert "$a" "$b4" "$a → $b 窗口后仍通（$b4）"

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
  ping_assert "$a" "$b4" "$a → $b IPv4 经 Relay（$b4）"
  ping_assert "$b" "$a4" "$b → $a IPv4 经 Relay（$a4）"

  note "断言 2：60s 观察窗内不出现 path=direct"
  flaps=0
  for i in $(seq 1 20); do
    sleep 3
    flaps=$(( flaps + $(grep -c "path=direct" "$ART_DIR/hz-node-$a.log" 2>/dev/null || true) \
                    + $(grep -c "path=direct" "$ART_DIR/hz-node-$b.log" 2>/dev/null || true) ))
  done
  (( flaps == 0 )) && pass "双对称 NAT 稳定走 Relay" || fail "出现 path=direct x${flaps}，双对称不应直连"

  note "断言 3：窗口结束时连通仍在"
  ping_assert "$a" "$b4" "$a → $b 窗口后仍通（$b4）"

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
  [[ -n $a_v6 && -n $b_v6 ]] || { fail "Node 缺少 v6 地址（a=$a_v6 b=$b_v6），HZ_WAN_V6 未生效？"; return 1; }
  if ip netns exec "$a_ns" ping -6 -c 2 -W 2 "$b_v6" >/dev/null 2>&1; then
    pass "底层 v6 直达（$a_v6 → $b_v6）"
  else
    fail "底层 v6 不通，v6 直连无从谈起"
  fi

  start_pair_with_relay "$a" "$b" || return 1
  wait_pair_mutual_view "$a" "$b" || return 1
  peer_addresses "$a" "$b"
  b4=$(peer_field "$a" ipv4); b6=$(peer_field "$a" ipv6)
  a4=$(peer_field "$b" ipv4); a6=$(peer_field "$b" ipv6)

  note "断言 1：Node Address 双向 ping（v4 与 ULA v6）"
  ping_assert "$a" "$b4" "$a → $b IPv4（$b4）"
  ping_assert "$b" "$a4" "$b → $a IPv4（$a4）"
  ping_assert "$a" "$b6" "$a → $b IPv6（$b6）" -6
  ping_assert "$b" "$a6" "$b → $a IPv6（$a6）" -6

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
  ping_assert "$a" "$b4" "$a → $b IPv4（$b4）"
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
  ping_assert "$a" "$b4" "$a → $b IPv4 经 Relay 恢复（$b4）"
  ping_assert "$b" "$a4" "$b → $a IPv4 经 Relay 恢复（$a4）"

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
  # 第三方 TUN 类网络工具在场时发生。
  note "PROXY_SIM：$a 先安装接管默认路由的黑洞 TUN，再启动 hzd"
  if ip netns exec "$ns" sh -c "
      ip tuntap add dev proxytun mode tun &&
      ip addr add 198.18.0.1/30 dev proxytun &&
      ip link set proxytun up &&
      ip route replace default dev proxytun
    "; then
    local blackhole
    blackhole=$(ip netns exec "$ns" ip route get 203.0.113.1 2>/dev/null | head -1)
    if [[ $blackhole == *proxytun* ]]; then
      pass "黑洞生效：未绑定流量（如 STUN 默认路由）已被第三方 TUN 吞下（$blackhole）"
    else
      fail "黑洞未生效：$blackhole"
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
  stun_line=$(grep "stun mapped endpoint discovered" "$ART_DIR/hz-node-$a.log" | tail -1)
  if [[ $stun_line == *"mapped=$expected "* ]]; then
    pass "$a：STUN Endpoint = $expected（真实出口，非黑洞地址）"
  else
    fail "$a：STUN Endpoint 异常（期望 $expected）：$stun_line"
  fi

  note "断言 2：黑洞之下仍建立 Direct Path、双向 ping"
  wait_for_log "$ART_DIR/hz-node-$a.log" "path=direct" "$a 升级 Direct Path（黑洞共存）" 90 || return 1
  wait_for_log "$ART_DIR/hz-node-$b.log" "path=direct" "$b 升级 Direct Path（黑洞共存）" 90 || return 1
  ping_assert "$a" "$b4" "$a → $b IPv4（$b4）"
  ping_assert "$b" "$a4" "$b → $a IPv4（$a4）"

  unset HZD_NODE_EXTRA
  (( FAILURES == 0 ))
}
