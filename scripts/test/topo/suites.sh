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
  # 可选 HZD_NODE_ENV 数组：额外注入 hzd 的环境变量（relay 场景用它传
  # HZD_RELAY_ADDR/HZD_RELAY_CA_PATH/HZD_FORCE_RELAY）；未设置时为空，老场景不受影响。
  local name="$1" key="$2" ns hostname
  ns=$(node_ns "$name"); hostname=$(node_hostname "$name")
  mkdir -p "$ART_DIR/state-$name"
  # 各 Node 独立 UTS 命名空间决定注册用的主机名（容器内所有 netns 共享同一个）
  ip netns exec "$ns" setsid unshare --uts sh -c \
    "echo $hostname > /proc/sys/kernel/hostname; \
     exec env HZD_STATE_DIR=$ART_DIR/state-$name HZD_SOCK_PATH=$ART_DIR/hzd-$name.sock \
       HZD_COORD_ADDR=http://203.0.113.1:443 HZD_WG_PORT=$HZ_WG_PORT \
       ${HZD_NODE_ENV[@]+"${HZD_NODE_ENV[@]}"} $BIN_DIR/hzd" \
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

  HZD_NODE_ENV=("HZD_RELAY_ADDR=https://203.0.113.1:$RELAY_PORT" \
                "HZD_RELAY_CA_PATH=$ART_DIR/relay-ca.pem" \
                "HZD_FORCE_RELAY=1")
  note "[$a/$b] 启动 hzd（HZD_FORCE_RELAY=1，对称 NAT 无直连路径）并注册"
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

  unset HZD_NODE_ENV
  (( FAILURES == 0 ))
}
