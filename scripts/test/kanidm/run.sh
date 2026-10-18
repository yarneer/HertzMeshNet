#!/usr/bin/env bash
# FR-2 / FR-11 门禁：真实 Kanidm 实例上的交互式登录集成测试（票 #10）。
# 流程：起 Kanidm（docker compose）→ setup.sh 配 persons/groups/oauth2 client →
# cargo test（--ignored，测试内部起 hz-coord 并用 reqwest 驱动 Kanidm 登录页）。
# 通过标准即票面 AC 五条，见 crates/hz-coord/tests/kanidm_login.rs。
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
HOST_PORT="${KANIDM_HOST_PORT:-18443}"

note() { printf '\n[kanidm-test] %s\n' "$*"; }

free_port() {
  python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

cleanup() {
  docker compose -f "$DIR/docker-compose.yml" down -v >/dev/null 2>&1 || true
  [ -n "${WORK_DIR:-}" ] && rm -rf "$WORK_DIR"
}
trap cleanup EXIT

WORK_DIR="$(mktemp -d /tmp/hznet-kanidm-test.XXXXXX)"
HTTP_PORT_1=$(free_port)
HTTP_PORT_2=$(free_port)

# 同端口可能被竞态抢占；重取直到不等于彼此。
while [ "$HTTP_PORT_2" = "$HTTP_PORT_1" ]; do HTTP_PORT_2=$(free_port); done

note "生成 server.toml（origin 指向宿主机映射端口）并启动 Kanidm"
# 上次残留的卷会让 setup 撞唯一性约束，先清掉保证每次全新实例。
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
# 证书与 server.toml 都写进 named volume，compose 只挂 volume，配置不用进 compose。
docker run --rm -v kanidm-test-data:/data -v "$WORK_DIR/server.toml":/data/server.toml:ro \
  docker.io/kanidm/server:1.8.0 kanidmd cert-generate >/dev/null
docker run --rm -v kanidm-test-data:/data -v "$WORK_DIR":/src:ro \
  --entrypoint /bin/cp docker.io/kanidm/tools:1.8.0 /src/server.toml /data/server.toml

KANIDM_HOST_PORT="$HOST_PORT" \
  docker compose -f "$DIR/docker-compose.yml" up -d >/dev/null

note "配置 Kanidm（persons、组、OAuth2 客户端）"
KANIDM_HOST_PORT="$HOST_PORT" \
KANIDM_REDIRECT_1="http://127.0.0.1:${HTTP_PORT_1}/oidc/callback" \
KANIDM_REDIRECT_2="http://127.0.0.1:${HTTP_PORT_2}/oidc/callback" \
  bash "$DIR/setup.sh" | tee "$WORK_DIR/credentials.json"
status=${PIPESTATUS[0]}
if [ "$status" -ne 0 ]; then
  note "setup.sh 失败（exit $status）"
  exit "$status"
fi
grep -q '^{' "$WORK_DIR/credentials.json" \
  || { note "credentials 文件缺 JSON 行"; exit 1; }

note "把 CA 证书复制到宿主机（coord 的 OIDC 客户端要信任它）"
SERVER_CONTAINER=$(docker compose -f "$DIR/docker-compose.yml" ps -q kanidm)
docker cp "$SERVER_CONTAINER:/data/chain.pem" "$WORK_DIR/chain.pem" >/dev/null

note "跑集成测试（真实 Kanidm + 真实 hz-coord，loopback）"
cd "$ROOT"
KANIDM_ISSUER="https://localhost:${HOST_PORT}" \
KANIDM_CA="$WORK_DIR/chain.pem" \
KANIDM_HTTP_PORT_1="$HTTP_PORT_1" \
KANIDM_HTTP_PORT_2="$HTTP_PORT_2" \
KANIDM_CREDENTIALS="$WORK_DIR/credentials.json" \
  cargo test -p hz-coord --test kanidm_login -- --ignored --nocapture
status=$?

if [ "$status" -eq 0 ]; then
  note "全部断言通过"
else
  note "断言失败；Kanidm 日志尾部："
  docker compose -f "$DIR/docker-compose.yml" logs kanidm 2>&1 | tail -30 || true
fi
exit "$status"
