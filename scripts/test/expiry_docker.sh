#!/usr/bin/env bash
# #11 有效期与重新登录 Docker 门禁（Seam A 等价面）。
# 真实组件：Kanidm（docker）+ hz-coord（宿主，OIDC + 60 秒登录 TTL）+ 特权容器内
# 三个真实 hzd（独立 netns + TUN + 真实 ping）。n1 交互式登录注册（到期对象），
# n2/n3 用带 Tag 的 Auth Key 注册（永不过期）。
# 断言（票面 AC 原文）：
#   有效期 1 分钟（HZ_EXPIRY_TTL_SECS=60）到期后 n1 与其他 Node 无法互 ping；
#   n2 的 Network Map 不再包含 n1；hz status 显示已过期；
#   带 Tag 的 n2/n3 不受影响仍互 ping；
#   重新登录后 NodeAddress/NodeName 不变、通信恢复、coord 库 node_key_pub 已更换。
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
KANIDM_DIR="$ROOT/scripts/test/kanidm"
IMAGE="${HZMN_TOPO_IMAGE:-hertzmesh-topo:latest}"
CARGO_CACHE="${HZMN_CARGO_CACHE:-/Users/lixin/Develop/.hmn-cache/cargo}"
HOST_PORT="${KANIDM_HOST_PORT:-18443}"
TTL_SECS="${HZ_EXPIRY_TTL_SECS:-60}"
BIND="${HZ_EXPIRY_COORD_BIND:-127.0.0.1}"
ISSUER="https://localhost:${HOST_PORT}/oauth2/openid/hznet-coord"
CTR=""
COORD_PID=""
WORK_DIR=""
ART=/tmp/hz-topo/run-expiry

PASS=0
FAIL=0
note() { printf '\n[expiry] %s\n' "$*"; }
pass() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$*"; }

free_port() {
  python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

cleanup() {
  [ -n "$COORD_PID" ] && kill "$COORD_PID" 2>/dev/null
  if [ -n "$CTR" ]; then
    [ -n "$WORK_DIR" ] && docker cp "$CTR:$ART" "$WORK_DIR/topo-artifacts" >/dev/null 2>&1 || true
    docker exec "$CTR" bash scripts/test/topo/topo.sh down >/dev/null 2>&1 || true
    docker rm -f "$CTR" >/dev/null 2>&1 || true
  fi
  [ -n "$WORK_DIR" ] && docker compose -f "$KANIDM_DIR/docker-compose.yml" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

WORK_DIR="$(mktemp -d /tmp/hznet-expiry-test.XXXXXX)"
COORD_GRPC=$(free_port)
COORD_HTTP=$(free_port)
while [ "$COORD_HTTP" = "$COORD_GRPC" ]; do COORD_HTTP=$(free_port); done
REDIRECT_2_PORT=$(free_port)

note "阶段 1：起真实 Kanidm（docker compose，端口 ${HOST_PORT}）"
docker volume rm -f kanidm-test-data kanidm-test-cli >/dev/null 2>&1 || true
cat > "$WORK_DIR/server.toml" <<EOF
version = "2"
bindaddress = "0.0.0.0:8443"
db_path = "/data/kanidm.db"
tls_chain = "/data/chain.pem"
tls_key = "/data/key.pem"
domain = "localhost"
origin = "https://localhost:${HOST_PORT}"
EOF
docker run --rm -v kanidm-test-data:/data -v "$WORK_DIR/server.toml":/data/server.toml:ro \
  docker.io/kanidm/server:1.8.0 kanidmd cert-generate >/dev/null
docker run --rm -v kanidm-test-data:/data -v "$WORK_DIR":/src:ro \
  --entrypoint /bin/cp docker.io/kanidm/tools:1.8.0 /src/server.toml /data/server.toml
KANIDM_HOST_PORT="$HOST_PORT" docker compose -f "$KANIDM_DIR/docker-compose.yml" up -d >/dev/null

note "阶段 2：配置 Kanidm（persons、组、OAuth2 客户端）"
KANIDM_HOST_PORT="$HOST_PORT" \
KANIDM_REDIRECT_1="http://127.0.0.1:${COORD_HTTP}/oidc/callback" \
KANIDM_REDIRECT_2="http://127.0.0.1:${REDIRECT_2_PORT}/oidc/callback" \
  bash "$KANIDM_DIR/setup.sh" > "$WORK_DIR/credentials.json"
setup_rc=${PIPESTATUS[0]}
[ "$setup_rc" -ne 0 ] && { note "setup.sh 失败（exit ${setup_rc}）"; exit "$setup_rc"; }
grep -q '^{' "$WORK_DIR/credentials.json" || { note "credentials 缺 JSON 行"; exit 1; }
SERVER_CONTAINER=$(docker compose -f "$KANIDM_DIR/docker-compose.yml" ps -q kanidm)
docker cp "$SERVER_CONTAINER:/data/chain.pem" "$WORK_DIR/chain.pem" >/dev/null
CLIENT_ID=$(python3 -c 'import json;print(json.loads([l for l in open("'"$WORK_DIR"'/credentials.json") if l.startswith("{")][-1])["client_id"])')
CLIENT_SECRET=$(python3 -c 'import json;print(json.loads([l for l in open("'"$WORK_DIR"'/credentials.json") if l.startswith("{")][-1])["client_secret"])')
ALICE_PW=$(python3 -c 'import json;print(json.loads([l for l in open("'"$WORK_DIR"'/credentials.json") if l.startswith("{")][-1])["alice_password"])')

note "阶段 3：构建宿主 hz-coord（debug 即可；本机 release 的 sqlx proc-macro dylib 曾损坏）并启动"
(cd "$ROOT" && cargo build -p hz-coord) || { note "hz-coord 构建失败"; exit 1; }
COORD_BIN="$ROOT/target/debug/hz-coord"
"$COORD_BIN" bootstrap --db "$WORK_DIR/coord.db" \
  --auth-key-expiry 1d --tag edge --json > "$WORK_DIR/tagged-key.json" || { note "bootstrap 失败"; exit 1; }
TAGGED_KEY=$(python3 -c 'import json;print(json.load(open("'"$WORK_DIR"'/tagged-key.json"))["auth_key"])')
HZ_COORD_LOGIN_NODE_TTL_SECS="$TTL_SECS" \
"$COORD_BIN" serve --db "$WORK_DIR/coord.db" \
  --listen "$BIND:$COORD_GRPC" --http-listen "$BIND:$COORD_HTTP" \
  --oidc-issuer "$ISSUER" --oidc-client-id "$CLIENT_ID" --oidc-client-secret "$CLIENT_SECRET" \
  --oidc-ca "$WORK_DIR/chain.pem" \
  --oidc-redirect-uri "http://127.0.0.1:${COORD_HTTP}/oidc/callback" \
  > "$WORK_DIR/coord.log" 2>&1 &
COORD_PID=$!
for _ in $(seq 1 30); do
  curl -fs "http://127.0.0.1:${COORD_HTTP}/healthz" >/dev/null 2>&1 && break
  sleep 1
done
curl -fs "http://127.0.0.1:${COORD_HTTP}/healthz" >/dev/null || { note "coord 未就绪"; exit 1; }

note "阶段 4：特权容器 + 拓扑（真实 TUN 与 netns）"
docker build -t "$IMAGE" -f "$ROOT/scripts/test/Dockerfile.topo" "$ROOT/scripts/test" >/dev/null
docker volume create hz-topo-target >/dev/null; docker volume create hz-topo-bin >/dev/null
CTR=$(docker run -d --privileged \
  -v "$ROOT:/src" -v "$CARGO_CACHE:/usr/local/cargo/registry" \
  -v hz-topo-target:/target -v hz-topo-bin:/out -w /src "$IMAGE" sleep infinity)
GATEWAY=$(docker exec "$CTR" getent hosts host.docker.internal 2>/dev/null | awk '{print $1; exit}')
[ -n "$GATEWAY" ] || { note "容器内无法解析 host.docker.internal（需要 Docker Desktop）"; exit 1; }
# /out 里可能有旧票的二进制；强制重建本分支的 hzd/hz。
docker exec "$CTR" rm -f /out/hz-coord /out/hz-relay /out/hzd /out/hz
docker exec "$CTR" bash scripts/test/topo/topo.sh build || { note "容器内二进制构建失败"; exit 1; }
docker exec "$CTR" bash scripts/test/topo/topo.sh up expiry-login || { note "拓扑搭建失败"; exit 1; }

# 节点 netns（192.168.100.0/24）出容器 eth0 的流量做 SNAT：Docker 的默认
# MASQUERADE 只覆盖自己的网段，拓扑内网段不罩的话节点到宿主网关的回包路径不通。
docker exec "$CTR" nft add table ip hz-expmasq >/dev/null 2>&1 || true
docker exec "$CTR" nft add chain ip hz-expmasq postrouting '{ type nat hook postrouting priority srcnat; policy accept; }' >/dev/null
docker exec "$CTR" nft add rule ip hz-expmasq postrouting ip saddr 192.168.100.0/24 oifname != 'hz-br-lan' masquerade
masq_rc=$?
[ "$masq_rc" -ne 0 ] && { note "SNAT 规则添加失败（exit ${masq_rc}）"; exit 1; }
docker exec "$CTR" ip netns exec hz-node-n1 python3 -c "
import socket, sys
s = socket.socket(); s.settimeout(5)
try:
    s.connect(('$GATEWAY', $COORD_GRPC))
except OSError as error:
    sys.exit('节点 netns 无法到达宿主 coord：{0}'.format(error))
" || { note "节点到宿主 coord 的连通性探测失败（可用 HZ_EXPIRY_COORD_BIND=0.0.0.0 重试）"; exit 1; }

docker_exec() { docker exec "$CTR" "$@"; }
hz_cli() { local node="$1"; shift; docker_exec ip netns exec "hz-node-$node" \
  env "HZD_SOCK_PATH=$ART/hzd-$node.sock" /out/hz "$@"; }
node_ping() { # 首包可能落在 WireGuard 冷启动握手的重传窗口内，允许重试（同 topo ping_assert）
  local node="$1" target="$2" attempt
  for attempt in 1 2 3 4 5; do
    if docker_exec ip netns exec "hz-node-$node" ping -c 3 -W 2 "$target"       > "$WORK_DIR/ping-$node.out" 2>&1; then
      return 0
    fi
    sleep 3
  done
  return 1
}

start_daemon() { # start_daemon <node>
  docker_exec mkdir -p "$ART/state-$1"
  docker_exec sh -c "ip netns exec hz-node-$1 setsid unshare --uts sh -c \
    'echo $1 > /proc/sys/kernel/hostname; \
     exec env HZD_STATE_DIR=$ART/state-$1 HZD_SOCK_PATH=$ART/hzd-$1.sock \
       HZD_COORD_ADDR=http://$GATEWAY:$COORD_GRPC HZD_WG_PORT=51820 \
       RUST_LOG=${HZD_TEST_LOG:-info} /out/hzd' \
    > $ART/hz-node-$1.log 2>&1 < /dev/null &"
  local i
  for i in $(seq 1 40); do
    docker_exec ip netns exec "hz-node-$1" test -S "$ART/hzd-$1.sock" 2>/dev/null && return 0
    sleep 0.5
  done
  fail "$1：hzd socket 未出现（见 $ART/hz-node-$1.log）"
  return 1
}

login_flow() { # login_flow <node>：后台 hz up → 驱动浏览器 → 等 CLI 终态
  local node="$1"
  docker_exec sh -c "ip netns exec hz-node-$node env HZD_SOCK_PATH=$ART/hzd-$node.sock \
    setsid sh -c '/out/hz up' > $ART/up-$node.out 2>&1; echo \$? > $ART/up-$node.rc" &
  local url="" i
  for i in $(seq 1 40); do
    url=$(docker_exec sh -c "grep -o 'http://[^ ]*' $ART/up-$node.out 2>/dev/null | head -1")
    [ -n "$url" ] && break
    sleep 0.5
  done
  [ -n "$url" ] || { fail "${node}：hz up 未打印登录链接"; return 1; }
  python3 "$ROOT/scripts/test/expiry/login_driver.py" \
    --url "$url" --issuer "$ISSUER" --username alice --password "$ALICE_PW" \
    --ca "$WORK_DIR/chain.pem"
  drive_rc=$?
  [ "$drive_rc" -ne 0 ] && { fail "${node}：浏览器侧登录失败（rc=${drive_rc}）"; return 1; }
  for i in $(seq 1 60); do
    docker_exec test -f "$ART/up-$node.rc" 2>/dev/null && break
    sleep 1
  done
  local rc
  rc=$(docker_exec sh -c "cat $ART/up-$node.rc 2>/dev/null || echo timeout")
  [ "$rc" = "0" ] || { fail "${node}：hz up 终态 rc=${rc}（见 $ART/up-$node.out）"; return 1; }
  pass "${node}：交互式登录完成（归属 alice，有效期 ${TTL_SECS}s）"
  return 0
}

status_field() { # status_field <node> <python 表达式（d 为 status JSON）>
  hz_cli "$1" status --json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print($2)"
}

wait_status() { # wait_status <node> <表达式> <label>
  local i
  for i in $(seq 1 120); do
    if status_field "$1" "$2" 2>/dev/null | grep -qx True; then return 0; fi
    sleep 1
  done
  fail "$3"
  return 1
}

note "阶段 5：起三个 Node 守护进程；n1 登录注册，n2/n3 带 Tag 注册"
for node in n1 n2 n3; do start_daemon "$node" || exit 1; done
login_flow n1 || exit 1
hz_cli n2 up --auth-key "$TAGGED_KEY" >/dev/null 2>&1 \
  && pass "n2：带 Tag Auth Key 注册成功" || { fail "n2：注册失败"; exit 1; }
hz_cli n3 up --auth-key "$TAGGED_KEY" >/dev/null 2>&1 \
  && pass "n3：带 Tag Auth Key 注册成功" || { fail "n3：注册失败"; exit 1; }

for node in n1 n2 n3; do
  wait_status "$node" "len(d.get('peers') or []) == 2" "${node}：应看到另外两个对端" || exit 1
done
N1_IPV4=$(status_field n1 "d['ipv4']")
N1_NAME=$(status_field n1 "d['name']")
KEY_BEFORE=$(sqlite3 "$WORK_DIR/coord.db" "SELECT lower(hex(node_key_pub)) FROM nodes WHERE name='$N1_NAME';")
N2_IPV4=$(status_field n2 "d['ipv4']")
N3_IPV4=$(status_field n3 "d['ipv4']")

# 心跳：长窗口（ping 重试 / 等到期）期间持续轮询 status，既保住 coord 侧
# 连接活跃，也把"守护进程失联"与"网络不通"区分开。
heartbeat_start() {
  ( while true; do
      for hb in n1 n2 n3; do
        if ! hz_cli "$hb" status --json > /dev/null 2>&1; then
          note "心跳：$hb status 失联 $(date +%H:%M:%S)"
        fi
      done
      sleep 5
    done ) &
  HEARTBEAT_PID=$!
}
heartbeat_stop() { [ -n "${HEARTBEAT_PID:-}" ] && kill "$HEARTBEAT_PID" 2>/dev/null; HEARTBEAT_PID=""; }
heartbeat_start

note "阶段 6：到期前互通（IPv4 直连，真实 ping）"
node_ping n1 "$N2_IPV4" >/dev/null 2>&1 && pass "到期前 n1 → n2 ping 通" || fail "到期前 n1 → n2 ping 不通"
node_ping n2 "$N1_IPV4" >/dev/null 2>&1 && pass "到期前 n2 → n1 ping 通" || fail "到期前 n2 → n1 ping 不通"
node_ping n2 "$N3_IPV4" >/dev/null 2>&1 && pass "到期前 n2 → n3 ping 通" || fail "到期前 n2 → n3 ping 不通"
[ "$FAIL" -gt 0 ] && { note "到期前基线失败，终止"; exit 1; }

note "阶段 7：等待到期（TTL=${TTL_SECS}s + 周期清扫）"
wait_status n1 "d.get('expired') is True" "n1：到期后 status 应显示已过期（TTL+清扫窗口内）" || {
  docker_exec sh -c "tail -20 $ART/hz-node-n1.log; tail -20 $WORK_DIR/coord.log" 2>/dev/null
  exit 1
}
pass "n1：hz status 已过期（已过期，请重新执行 hz up 登录）"

hz_cli n1 status 2>/dev/null | grep -q "已过期" \
  && pass "n1：hz status 文案含「已过期」" || fail "n1：hz status 文案缺「已过期」"

node_ping n1 "$N2_IPV4" >/dev/null 2>&1 && fail "到期后 n1 → n2 仍可通信" || pass "到期后 n1 → n2 无法通信"
node_ping n1 "$N3_IPV4" >/dev/null 2>&1 && fail "到期后 n1 → n3 仍可通信" || pass "到期后 n1 → n3 无法通信"
status_field n2 "'n1' not in [p['name'] for p in (d.get('peers') or [])]" | grep -qx True \
  && pass "n2：Network Map 已移除 n1" || fail "n2：Network Map 仍包含 n1"
node_ping n2 "$N3_IPV4" >/dev/null 2>&1 \
  && pass "带 Tag 的 n2 → n3 不受有效期影响" || fail "带 Tag 的 n2 → n3 被有效期误伤"

note "阶段 8：重新登录（轮换 Node Key，保身份）"
login_flow n1 || exit 1
wait_status n1 "d.get('registered') is True" "n1：重新登录后应回到已注册" || exit 1
AFTER_IPV4=$(status_field n1 "d['ipv4']")
AFTER_NAME=$(status_field n1 "d['name']")
KEY_AFTER=$(sqlite3 "$WORK_DIR/coord.db" "SELECT lower(hex(node_key_pub)) FROM nodes WHERE name='$AFTER_NAME';")
[ "$AFTER_IPV4" = "$N1_IPV4" ] && pass "重新登录后 Node Address 不变（${AFTER_IPV4}）" || fail "Node Address 变了：$N1_IPV4 → $AFTER_IPV4"
[ "$AFTER_NAME" = "$N1_NAME" ] && pass "重新登录后 Node Name 不变（${AFTER_NAME}）" || fail "Node Name 变了：$N1_NAME → $AFTER_NAME"
[ -n "$KEY_BEFORE" ] && [ "$KEY_AFTER" != "$KEY_BEFORE" ] \
  && pass "coord 库 node_key_pub 已更换" || fail "node_key_pub 未轮换（before=$KEY_BEFORE after=${KEY_AFTER}）"
EXPIRY_AFTER=$(sqlite3 "$WORK_DIR/coord.db" "SELECT expires_at_unix FROM nodes WHERE name='$AFTER_NAME';")
NOW=$(date +%s)
[ "$EXPIRY_AFTER" -gt "$NOW" ] && pass "重新登录已续期（expires=$EXPIRY_AFTER > now=${NOW}）" || fail "未续期"

wait_status n2 "'n1' in [p['name'] for p in (d.get('peers') or [])]" "n2：重新登录后 Map 应重新包含 n1" || true
# n1 重新订阅后要先拿到全量 Map 并重建对端，再给路径建立（重连退避上限 30s）留足窗口。
wait_status n1 "'n2' in [p['name'] for p in (d.get('peers') or [])]" "n1：重新登录后 Map 应重新包含 n2" || true
node_ping n1 "$N2_IPV4" >/dev/null 2>&1 && pass "重新登录后 n1 → n2 通信恢复" || fail "重新登录后 n1 → n2 仍不通"

note "结果：PASS=$PASS FAIL=${FAIL}（TTL=${TTL_SECS}s；产物 ${WORK_DIR}）"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
