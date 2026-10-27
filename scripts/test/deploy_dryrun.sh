#!/usr/bin/env bash
# #18 部署脚本干跑：在全新 debian:bookworm 容器（无 systemd）里执行
# server-bootstrap.sh 的 --skip-packages --no-systemctl 路径（哑二进制代替
# musl 产物），断言全部文件产物、三次 SNI 分流表与 nginx 配置可用性
# （nginx -t 必须通过），再干跑 backup/restore/hz-bootstrap/upgrade 的文件
# 操作路径，以及 certs.sh 的 --self-signed 路径。kanidm-init.sh 与 certs.sh 的
# 正式证书路径需要真实 Kanidm/ACME，不在干跑范围（由 shellcheck 覆盖语法层）。
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${DIR}/../.." && pwd)"
IMAGE="${DEPLOY_DRYRUN_IMAGE:-debian:bookworm}"

INNER_SCRIPT="$(mktemp /tmp/hznet-dryrun-inner.XXXXXX.sh)"
trap 'rm -f "${INNER_SCRIPT}"' EXIT
cat > "${INNER_SCRIPT}" <<'INNER'
set -eu
export DEBIAN_FRONTEND=noninteractive

FAILS=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; FAILS=$((FAILS + 1)); }
assert_contains() {
  if grep -q -- "$2" "$1"; then pass "$1 contains: $2"
  else fail "expected $2 in $1"; fi
}
assert_regex() {
  if grep -qE -- "$2" "$1"; then pass "$1 matches: $2"
  else fail "expected regex $2 in $1"; fi
}
assert_absent() {
  if grep -q -- "$2" "$1"; then fail "unexpected $2 in $1"
  else pass "$1 free of: $2"; fi
}
assert_file() {
  if [ -f "$1" ]; then pass "file exists: $1"
  else fail "missing file: $1"; fi
}
# 每个子域名一张证书、SAN 只含自身：多 SAN 证书会让浏览器复用 coord 的连接
# 请求 auth（三子域名同 IP），被 SNI 分流送错后端。
assert_single_san() {
  local sans
  sans=$(openssl x509 -in "/etc/hznet/tls/$1/fullchain.pem" -noout -text \
    | grep -o 'DNS:[^,[:space:]]*' | tr '\n' ' ')
  if [ "${sans}" = "DNS:$1.dryrun.example " ]; then pass "$1 cert SAN only $1.dryrun.example"
  else fail "$1 cert SAN = ${sans:-<none>} (expect only DNS:$1.dryrun.example)"; fi
}

echo "== 容器初始化（nginx + stream 模块、openssl、sqlite3、python3）"
apt-get update -qq
apt-get install -y -qq nginx libnginx-mod-stream openssl sqlite3 python3 curl ca-certificates >/dev/null

echo "== 构造哑分发目录（干跑只验证部署脚本与 nginx 配置，不构建 musl 产物）"
for d in linux-x86_64 darwin-arm64; do
  mkdir -p "/tmp/dist/$d" "/tmp/dist2/$d"
done
for b in hz-coord hz-relay hzd hz; do
  printf '#!/bin/sh\necho dummy-v1\n' > "/tmp/dist/linux-x86_64/$b"
  printf '#!/bin/sh\necho dummy-v2\n' > "/tmp/dist2/linux-x86_64/$b"
  printf '#!/bin/sh\necho dummy\n' > "/tmp/dist/darwin-arm64/$b"
  chmod +x "/tmp/dist/linux-x86_64/$b" "/tmp/dist2/linux-x86_64/$b" "/tmp/dist/darwin-arm64/$b"
done

echo "== 干跑 server-bootstrap.sh（--skip-packages --no-systemctl）"
/work/scripts/deploy/server-bootstrap.sh \
  --domain dryrun.example --dist /tmp/dist --skip-packages --no-systemctl \
  > /tmp/bootstrap.log 2>&1
pass "server-bootstrap.sh exit 0"

echo "== 断言：环境文件"
assert_file /etc/default/hz-coord
assert_file /etc/default/hz-relay
assert_file /etc/default/hzd
assert_contains /etc/default/hz-coord '--db /var/lib/hz-coord/hznet.db'
assert_contains /etc/default/hz-coord '--listen 127.0.0.1:50051'
assert_contains /etc/default/hz-coord '--http-listen 127.0.0.1:8080'
assert_contains /etc/default/hz-coord '--public-url https://coord.dryrun.example'
assert_contains /etc/default/hz-coord '--public-grpc-addr https://coord.dryrun.example'
assert_contains /etc/default/hz-coord '--dist-dir /var/lib/hz-coord/dist'
assert_absent  /etc/default/hz-coord '@DOMAIN@'
if grep '^HZ_COORD_ARGS=' /etc/default/hz-coord | grep -q -- '--oidc-'; then
  fail "HZ_COORD_ARGS should not carry --oidc-* before kanidm-init"
else pass "HZ_COORD_ARGS free of --oidc-* (added later by kanidm-init.sh)"; fi
assert_contains /etc/default/hz-relay 'HZ_RELAY_TOKEN=@RELAY_TOKEN@'
assert_contains /etc/default/hz-relay '--listen 127.0.0.1:8444'
assert_contains /etc/default/hz-relay '--stun-listen 0.0.0.0:3478'
assert_contains /etc/default/hz-relay '--coord http://127.0.0.1:50051'
assert_contains /etc/default/hz-relay '--tls-cert /etc/hznet/tls/relay/fullchain.pem'
assert_absent  /etc/default/hz-relay '@DOMAIN@'
assert_contains /etc/default/hzd 'HZD_COORD_ADDR=https://coord.dryrun.example'
assert_contains /etc/default/hzd 'HZD_RELAY_ADDR=https://relay.dryrun.example'

echo "== 断言：systemd 单元"
for u in hz-coord hz-relay hzd kanidm; do
  assert_file "/etc/systemd/system/${u}.service"
done

echo "== 断言：nginx 443 SNI 分流（三条 map 项）"
STREAM_CONF=/etc/nginx/streams-enabled/hznet.conf
assert_file "${STREAM_CONF}"
sni_count=$(grep -cE '(coord|relay|auth)\.dryrun\.example +127\.0\.0\.1:84(43|44|45)' "${STREAM_CONF}")
if [ "${sni_count}" = "3" ]; then pass "SNI map has 3 subdomain entries"
else fail "SNI map entries = ${sni_count} (expect 3)"; fi
assert_regex "${STREAM_CONF}" 'coord\.dryrun\.example\s+127\.0\.0\.1:8443'
assert_regex "${STREAM_CONF}" 'relay\.dryrun\.example\s+127\.0\.0\.1:8444'
assert_regex "${STREAM_CONF}" 'auth\.dryrun\.example\s+127\.0\.0\.1:8445'
if grep -q 'streams-enabled' /etc/nginx/nginx.conf; then pass "nginx.conf gained stream include"
else fail "nginx.conf missing stream include"; fi
assert_file /etc/nginx/sites-enabled/hznet
if [ ! -e /etc/nginx/sites-enabled/default ]; then pass "default site disabled"
else fail "default site still enabled"; fi
assert_contains /etc/nginx/sites-enabled/hznet 'grpc_pass grpc://127.0.0.1:50051'
assert_contains /etc/nginx/sites-enabled/hznet 'location /hz.v1.Coord/'
assert_contains /etc/nginx/sites-enabled/hznet 'proxy_pass http://127.0.0.1:8080'
assert_contains /etc/nginx/sites-enabled/hznet '/admin/'
assert_contains /etc/nginx/sites-enabled/hznet '/admin/api/'
assert_contains /etc/nginx/sites-enabled/hznet '/admin/oidc/callback'
assert_contains /etc/nginx/sites-enabled/hznet 'listen 127.0.0.1:8443 ssl http2'
assert_contains /etc/nginx/sites-enabled/hznet 'acme-challenge'
assert_contains /etc/nginx/sites-enabled/hznet 'if ($host != "coord.dryrun.example")'
assert_contains /etc/nginx/sites-enabled/hznet 'return 421'

echo "== 断言：占位证书与 Kanidm 配置"
for sub in coord relay auth; do
  assert_file "/etc/hznet/tls/${sub}/fullchain.pem"
  assert_file "/etc/hznet/tls/${sub}/privkey.pem"
  assert_single_san "${sub}"
done
assert_contains /etc/kanidm/server.toml 'domain = "auth.dryrun.example"'
assert_contains /etc/kanidm/server.toml 'origin = "https://auth.dryrun.example"'
assert_contains /etc/kanidm/server.toml '/etc/hznet/tls/auth/fullchain.pem'
assert_file /var/lib/hz-coord/dist/linux-x86_64/hz-coord
assert_file /var/lib/hz-coord/dist/darwin-arm64/hzd

echo "== 断言：nginx -t"
if nginx -t 2>/tmp/nginx-t.err; then pass "nginx -t OK"
else fail "nginx -t failed"; cat /tmp/nginx-t.err >&2; fi

echo "== 断言：coord vhost 对其他子域名的请求返回 421（浏览器换连接重试）"
nginx
code_for() {
  curl -sk -o /dev/null -w '%{http_code}' --resolve "$1:8443:127.0.0.1" "https://$1:8443/healthz" || true
}
code=$(code_for auth.dryrun.example)
if [ "${code}" = "421" ]; then pass "Host auth.dryrun.example on coord vhost -> 421"
else fail "Host auth.dryrun.example on coord vhost -> ${code} (expect 421)"; fi
code=$(code_for coord.dryrun.example)
if [ "${code}" != "421" ]; then pass "Host coord.dryrun.example passes through (${code}, no backend in dryrun)"
else fail "Host coord.dryrun.example unexpectedly 421"; fi
nginx -s stop

echo "== 幂等：再跑一次 server-bootstrap.sh"
if /work/scripts/deploy/server-bootstrap.sh \
    --domain dryrun.example --dist /tmp/dist --skip-packages --no-systemctl \
    >/tmp/bootstrap2.log 2>&1; then
  pass "server-bootstrap.sh re-run exit 0"
  if grep -q 'HZ_RELAY_TOKEN=@RELAY_TOKEN@' /etc/default/hz-relay; then
    pass "re-run kept existing env files"
  else fail "re-run clobbered env files"; fi
else
  fail "server-bootstrap.sh re-run non-zero"
fi

echo "== backup.sh / restore.sh 干跑"
sqlite3 /tmp/source.db 'CREATE TABLE node(id INTEGER PRIMARY KEY, name TEXT); INSERT INTO node(name) VALUES ("n1");'
/work/scripts/deploy/backup.sh --db /tmp/source.db --dest /tmp/backups > /tmp/backup.log 2>&1
pass "backup.sh exit 0"
BK=$(ls -1 /tmp/backups/hz-coord-*.db | head -1)
assert_file "${BK}"
if [ "$(sqlite3 "${BK}" 'PRAGMA integrity_check;')" = "ok" ]; then pass "backup integrity ok"
else fail "backup integrity bad"; fi
if [ "$(sqlite3 "${BK}" 'SELECT count(*) FROM node;')" = "1" ]; then pass "backup content intact"
else fail "backup content wrong"; fi
/work/scripts/deploy/restore.sh --backup "${BK}" --db /tmp/restored.db --no-systemctl > /tmp/restore.log 2>&1
pass "restore.sh exit 0"
if [ "$(sqlite3 /tmp/restored.db 'SELECT count(*) FROM node;')" = "1" ]; then pass "restored db content intact"
else fail "restored db content wrong"; fi

echo "== certs.sh --self-signed 干跑（每个子域名各一张占位证书）"
rm -f /etc/hznet/tls/*/fullchain.pem
/work/scripts/deploy/certs.sh --domain dryrun.example --self-signed --no-systemctl > /tmp/certs.log 2>&1
pass "certs.sh --self-signed exit 0"
for sub in coord relay auth; do
  assert_single_san "${sub}"
done
assert_contains /tmp/certs.log 'systemctl reload nginx'

echo "== hz-bootstrap.sh 干跑（hz-coord 用 JSON 桩替代）"
cat > /usr/local/bin/hz-coord <<'SHIM'
#!/usr/bin/env bash
echo "$*" > /tmp/hzcoord-args
echo '{"auth_key":"hzkey_dryrun_1","expires_at_unix":4102444800,"admin":"ops","relay_token":"relaytok_dryrun_1"}'
SHIM
chmod +x /usr/local/bin/hz-coord
/work/scripts/deploy/hz-bootstrap.sh --admin ops --no-systemctl > /tmp/hzboot.log 2>&1
pass "hz-bootstrap.sh exit 0"
assert_contains /etc/default/hz-relay 'HZ_RELAY_TOKEN=relaytok_dryrun_1'
assert_absent  /etc/default/hz-relay '@RELAY_TOKEN@'
assert_contains /tmp/hzboot.log 'hzkey_dryrun_1'
assert_contains /tmp/hzcoord-args '--tag server'
assert_contains /tmp/hzboot.log 'Tags：server'

echo "== healthcheck.sh 干跑（无后端：nginx 与证书 PASS，coord/relay/kanidm/dns FAIL）"
set +e
/work/scripts/deploy/healthcheck.sh --domain dryrun.example --cert-days 14 > /tmp/hc.log 2>&1
hc_rc=$?
set -eu
if [ "${hc_rc}" -ne 0 ]; then pass "healthcheck.sh non-zero without backends"
else fail "healthcheck.sh exit 0 without backends"; fi
assert_contains /tmp/hc.log 'PASS nginx -t'
assert_contains /tmp/hc.log 'PASS cert coord'
assert_contains /tmp/hc.log 'PASS cert relay'
assert_contains /tmp/hc.log 'PASS cert auth'
assert_contains /tmp/hc.log 'FAIL coord '
assert_contains /tmp/hc.log 'FAIL relay '
assert_contains /tmp/hc.log 'FAIL kanidm '
assert_contains /tmp/hc.log 'FAIL dns coord.dryrun.example'
if grep -q '^SKIP ' /tmp/hc.log; then fail "dryrun should not SKIP (nginx, openssl, getent are installed)"
else pass "healthcheck.sh printed no SKIP"; fi

echo "== upgrade.sh 干跑"
/work/scripts/deploy/upgrade.sh --dist /tmp/dist2 --no-systemctl > /tmp/upgrade.log 2>&1
pass "upgrade.sh exit 0"
if grep -q 'dummy-v2' /usr/local/bin/hz-coord; then pass "hz-coord binary replaced"
else fail "hz-coord binary not replaced"; fi
if grep -q 'dummy-v2' /var/lib/hz-coord/dist/linux-x86_64/hz-coord; then pass "dist dir refreshed"
else fail "dist dir not refreshed"; fi

echo ""
if [ "${FAILS}" = "0" ]; then
  echo "deploy dryrun: ALL PASS"
  exit 0
fi
echo "deploy dryrun: ${FAILS} FAILURES"
exit 1
INNER

chmod +x "${INNER_SCRIPT}"
docker run --rm -v "${REPO}:/work:ro" -v "${INNER_SCRIPT}:/inner.sh:ro" "${IMAGE}" bash /inner.sh