# HzNet 云主机部署与运维手册

> 对应 issue #18（M4）。本手册与 `scripts/deploy/`、`packaging/deploy/` 配套，
> 命令按顺序照抄即可完成部署。**真实云主机上的部署（含三机组网验收）是
> 人工步骤（G2）**：本手册把每一步准备成可直接粘贴的命令，剩下的执行需要
> 你自己的云主机、已备案域名与凭据。

## 1. 架构与端口

单台大陆云主机，三个子域名共用公网 TCP 443，按 TLS SNI 分流（ADR-0004）：

```
                    公网
                      │
        TCP 443 ──────┼──────── nginx stream（ssl_preread 按 SNI 分流）
        TCP 80  ──────┼──────── nginx http（ACME HTTP-01 + 跳转 https）
        UDP 3478 ─────┼──────── hz-relay（STUN，直接监听）
        UDP 51820 ────┼──────── hzd（云主机自身作为 Node 时，WireGuard 直连，§6.2）
                      │
        coord.<域名> ─┤→ 127.0.0.1:8443  nginx https（终止 TLS）
                      │      ├─ /hz.v1.Coord/*  ─→ grpc(h2c) → 127.0.0.1:50051  hz-coord（gRPC 明文）
                      │      └─ 其余 HTTP ─→ 127.0.0.1:8080  hz-coord
                      │            /install.sh /dl/ /oidc/ /healthz
                      │            /admin/ /admin/login /admin/oidc/callback /admin/api/
        relay.<域名> ─┤→ 127.0.0.1:8444  hz-relay（自带 TLS 终止）
        auth.<域名>  ─┤→ 127.0.0.1:8445  kanidmd（自带 TLS 终止）

        127.0.0.1:9100  hz-coord /metrics      127.0.0.1:9101  hz-relay /metrics
```

| 端口 | 协议 | 归属 | 用途 |
|---|---|---|---|
| 443 | TCP | nginx stream | 三个子域名按 SNI 分流（FR-6/FR-9/ADR-0004） |
| 80 | TCP | nginx http | ACME HTTP-01 验证、跳转 https |
| 3478 | UDP | hz-relay | STUN 公网 Endpoint 发现（FR-8） |
| 51820 | UDP | hzd | 云主机自身作为 Node 时的 WireGuard 直连；须用 `HZD_WG_PORT` 固定（§6.2） |
| 9100 / 9101 | TCP | hz-coord / hz-relay | Prometheus /metrics，仅本机 |

**gRPC 为什么可以这样代理（代码事实，非猜测）**：Node 侧 hzd 以
`HZD_COORD_ADDR=https://coord.<域名>` 连接，走 tonic 的 `ClientTlsConfig`
（系统 CA 校验 + ALPN h2，见 `crates/hz-core/src/coord_client.rs` 的
`connect_tls_channel`）。它只要求"所连地址是有效 TLS"，不要求 TLS 一直到
tonic 进程；因此 nginx 在 127.0.0.1:8443 终止 TLS 后，把 gRPC 以明文 h2
（`grpc_pass grpc://127.0.0.1:50051`）转给 hz-coord 完全满足客户端。gRPC
路径前缀 `/hz.v1.Coord/` 来自 proto 的 `package hz.v1; service Coord`。
Relay 与 Kanidm 需要 TLS 透传，因为它们各自在进程内终止 TLS（hz-relay 用
`--tls-cert/--tls-key`，Kanidm 的 server.toml 要求 `tls_chain/tls_key`）。

## 2. 前置条件（G2）

1. **大陆云主机**一台（阿里云/腾讯云等，独立公网 IP，Ubuntu 22.04+/Debian 12）。
2. **已备案域名**一个：大陆主机对外提供 80/443 服务必须使用已备案域名。
3. **DNS 三条 A 记录**：`coord.<域名>`、`relay.<域名>`、`auth.<域名>` → 公网 IP。
4. **安全组**放行：TCP 443、TCP 80、UDP 3478；云主机自身作为 Node（§6.2）时再放行
   UDP 51820（其余端口一律不开；9100/9101 只绑 127.0.0.1，不入安全组）。
5. **分发目录 `dist/`**（不在 git 里，见 `.gitignore`）：布局
   `dist/<平台>/{hzd,hz}` 与 `dist/linux-x86_64/{hz-coord,hz-relay,hzd,hz}`。
   两个来源：
   - GitHub Release 产物（`.github/workflows/release.yml` 构建）：下载
     `dist-linux-x86_64`、`dist-linux-aarch64`、`dist-darwin-arm64`，按平台
     名并成 `dist/<平台>/` 目录；
   - 或自建：`cargo build --release --target x86_64-unknown-linux-musl -p hzd -p hz -p hz-coord -p hz-relay`，
     把产物拷进 `dist/linux-x86_64/`（aarch64 用 `cross`，macOS 用本机
     `cargo build --release`）。
   dist 目录同时是 hz-coord 的 /dl 分发源（FR-13），必须包含 Node 平台
   （linux-x86_64、linux-aarch64、darwin-arm64）。

## 3. 证书（ACME）

部署脚本先装 30 天占位自签证书把服务拉起，随后用 acme.sh 换正式证书：

```sh
sudo bash scripts/deploy/certs.sh --domain <域名> --account-email <你的邮箱>
```

- HTTP-01 走 nginx 80 端口 webroot；coord / relay / auth **每个子域名各一张证书**，
  证书里只有自身的名字。
- 分别安装到 `/etc/hznet/tls/{coord,relay,auth}/`；续期时各自重载使用者：coord → nginx
  reload，relay → 重启 hz-relay，auth → 重启 kanidm（后两者只在启动时读证书）。
- 续期由 acme.sh 自带的定时任务自动完成（`crontab -l` 可见），无需人工干预；
  强制续期加 `--force`。
- 测试环境可重生成占位证书：`sudo bash scripts/deploy/certs.sh --domain <域名> --self-signed`。

为什么不用一张证书覆盖三个子域名：三个子域名解析到同一 IP，443 由 nginx 按 SNI 把**整条
TCP 连接**分给 coord / relay / Kanidm。证书若同时覆盖 `auth.<域名>`，浏览器会复用已经
连到 coord 的 HTTP/2 连接去请求 `auth.<域名>`（连接合并），请求被送进 hz-coord，表现为
交互式登录时 Kanidm 登录页 404（如 `/ui/login/begin`），回调方向也可能落进 Kanidm。
单域名证书让浏览器不再合并连接；另外 coord 的 TLS vhost 对 Host 不是 `coord.<域名>` 的
请求返回 421（Misdirected Request），浏览器会换一条新连接重试，作为兜底。

**已部署环境的迁移**（v0.1.3 及更早用 `certs.sh` 签过一张三 SAN 证书）：

```sh
cd <仓库目录> && git pull                       # 取到新版 certs.sh 与 nginx 模板
sudo bash scripts/deploy/certs.sh --domain <域名> --account-email <你的邮箱>
sudo sed "s/@DOMAIN@/<域名>/g" packaging/deploy/nginx/hznet-http.conf.template \
  | sudo tee /etc/nginx/sites-available/hznet >/dev/null
sudo nginx -t && sudo systemctl reload nginx
```

- `certs.sh` 发现已安装的证书含其他子域名时，自动为每个子域名重签单域名证书并安装、
  重载对应服务（Let's Encrypt 对同一组域名每周有签发次数限制，迁移只需执行一次）。
- 第二步把 421 规则带进 nginx（`server-bootstrap.sh` 重跑也会重写该文件）。
- 自检：`openssl s_client -connect coord.<域名>:443 -servername auth.<域名> </dev/null
  2>/dev/null | openssl x509 -noout -ext subjectAltName` 应只列出 `auth.<域名>`；浏览器
  需关闭已打开的标签页或重启，丢掉旧的合并连接。

自检：

```sh
curl -fsS https://coord.<域名>/healthz   # 预期 ok
curl -fsS https://auth.<域名>/status     # 预期 true（kanidm 已启动）
```

同一组检查，外加 Relay、nginx、三张证书到期与 DNS A 记录，用 §7.6 的 `healthcheck.sh`。

## 4. 部署步骤（G2，照抄）

在云主机上以 root 执行（仓库与 dist 一起放上去，脚本从仓库根运行）：

```sh
git clone git@github.com:yarneer/HertzMeshNet.git   # 或 rsync 上传工作区
cd HertzMeshNet
sudo bash scripts/deploy/server-bootstrap.sh \
  --domain <域名> \
  --dist <dist 目录绝对路径> \
  --kanidm-tarball <kanidm 发布包路径或URL，可选>
```

`server-bootstrap.sh` 幂等，做这些事：

1. 安装依赖（nginx + stream 模块、openssl、sqlite3、curl、python3）；
2. 安装 `hz-coord`/`hz-relay`/`hzd`/`hz` 到 `/usr/local/bin`，并把 dist 拷到
   `/var/lib/hz-coord/dist`；
3. 写 `/etc/default/hz-coord`、`/etc/default/hz-relay`（Relay Token 占位）、
   `/etc/default/hzd`（已含 `HZD_COORD_ADDR` 与 `HZD_RELAY_ADDR`）；
4. 安装 systemd 单元（hz-coord / hz-relay / hzd / kanidm）；
5. 写 `/etc/kanidm/server.toml` 与 nginx 的 443 SNI 分流、coord TLS 终止、
   80 端口 ACME 配置，`nginx -t` 校验后拉起全部服务。

**Kanidm 二进制**：官方发布包（GitHub `kanidm/kanidm` Releases，选
linux-x86_64/aarch64 的 tar.gz，内含 `kanidmd` 与 `kanidm`）。两种装法：

```sh
# 装法一：随 bootstrap 一起装
sudo bash scripts/deploy/server-bootstrap.sh --domain <域名> --dist <dist> \
  --kanidm-tarball https://github.com/kanidm/kanidm/releases/download/<版本>/kanidm-linux-x86_64.tar.gz

# 装法二：手工解开任意路径后
sudo tar -xzf kanidm-linux-x86_64.tar.gz -C /tmp \
  && sudo find /tmp -type f \( -name kanidmd -o -name kanidm \) \
       -exec install -m 0755 {} /usr/local/bin/ \; \
  && sudo systemctl enable --now kanidm
```

（规格要求"我方服务不用容器"；Kanidm 作为独立上游组件以原生二进制 +
systemd 运行，与 hz-coord/hz-relay 同一形态。）

此时 coord 已可对公网提供 `/install.sh` 与 `/dl/`。`/admin/` 会跳到
`/admin/login`；§5 写好 OIDC 之前，该页返回「未配置交互式登录」。登录与 Relay
还不可用，继续 §5、§6。

## 5. Kanidm 初始化（G2）

前提：§3 的正式证书已装好（本脚本用系统 CA 校验 `auth.<域名>`）。

```sh
sudo bash scripts/deploy/kanidm-init.sh --domain <域名> --admin-name <第一个管理员的登录名>
```

脚本做的事（API 流程实测自 Kanidm 1.8，与 `scripts/test/kanidm/setup.sh`
同一套结论）：

1. `kanidmd recover-account admin/idm_admin` 拿回内置管理员口令并登录；
2. 创建组 `hznet_admins`、`hznet_users`，创建第一个 User 并生成随机口令；
3. 创建 OAuth2 客户端 `hznet-coord`（机密客户端 + PKCE + 严格回调
   `https://coord.<域名>/oidc/callback` 与 Admin Console 的
   `https://coord.<域名>/admin/oidc/callback`，scopes openid/profile/groups）；
4. 把 `--oidc-*` 连同 client secret 写进 `/etc/default/hz-coord`（权限 0600）
   并重启 hz-coord，等待 `/healthz` 恢复。

结束打印一行 JSON（**口令与 secret 仅此一次显示，立即保存到密码管理器**）：

```json
{"client_id":"hznet-coord","client_secret":"...","issuer":"https://auth.<域名>/oauth2/openid/hznet-coord","redirect_uri":"https://coord.<域名>/oidc/callback","admin_redirect_uri":"https://coord.<域名>/admin/oidc/callback","admin_name":"...","admin_password":"..."}
```

`hznet_admins` 的成员即 HzNet Admin（FR-11，经 OIDC groups claim 传给
Coordination Server）。此后加管理员就是往 Kanidm 组里加人：

```sh
kanidm group add-members hznet_admins <某人>
```

### 5.1 登录 Admin Console

不需要第二个 OAuth2 客户端，也不需要新的回调路径。`kanidm-init.sh` 已经在
同一个 `hznet-coord` 客户端上登记两条严格回调：

- Node 交互登录：`https://coord.<域名>/oidc/callback`
- Admin Console：`https://coord.<域名>/admin/oidc/callback`

nginx 也不必为 `/admin` 再写一条 `location`。coord 的 TLS vhost 里现有的
`location /` 把 `/admin/`、`/admin/login`、`/admin/oidc/callback` 和
`/admin/api/` 反代到 `127.0.0.1:8080`（模板
`packaging/deploy/nginx/hznet-http.conf.template`）。gRPC 仍只走
`location /hz.v1.Coord/`。改过旧配置后：

```sh
sudo sed "s/@DOMAIN@/<域名>/g" packaging/deploy/nginx/hznet-http.conf.template \
  | sudo tee /etc/nginx/sites-available/hznet >/dev/null
sudo nginx -t && sudo systemctl reload nginx
```

浏览器登录（证书与 §5 已完成）：

1. 打开 `https://coord.<域名>/admin/`。未登录先到 `/admin/login`，再跳到
   Kanidm。授权请求里的 `redirect_uri` 是
   `https://coord.<域名>/admin/oidc/callback`。
2. 用 `hznet_admins` 的成员登录（§5 打印的第一个管理员，或
   `kanidm group add-members` 加进去的人）。不在组里会看到「无权进入」，不会发会话。
3. 成功后回到 `/admin/`。会话 cookie 名 `hz_admin`，`Path=/admin`（因此
   `/admin/api` 会带上），`HttpOnly`，回调是 https 时带 `Secure`，有效期 12
   小时。会话只在 hz-coord 进程内存里，`systemctl restart hz-coord` 之后要重新登录。
4. 页面是 Node 列表、Auth Key 签发与吊销（明文只出现一次，没有清单）、Policy
   只读、健康与一次打包备份、部署向导（只给可复制命令）。没有重启、升级或任意 shell。

未登录自检（不需要浏览器；正式证书已装时不要加 `-k`）：

```sh
curl -sI https://coord.<域名>/admin/ | tr -d '\r' | head -n 20
# 预期：HTTP/2 307，location: /admin/login

curl -sS -D- -o /tmp/admin-me.json https://coord.<域名>/admin/api/me
# 预期：状态行 401。/tmp/admin-me.json 为
# {"error":"unauthenticated","message":"需要 Admin 会话"}

curl -sI http://127.0.0.1:8080/admin/ | tr -d '\r' | head -n 8
# 绕过 nginx，同样应是 307。本机通、公网不通时，问题在 nginx 或证书，不在 hz-coord。
```

## 6. bootstrap 与首个 Node 接入（G2）

> Node 侧的完整安装、注册、验证、升级与卸载步骤单独成篇：[install-guide.md](install-guide.md)。本节只讲服务器侧的 bootstrap 与首台验收。

### 6.1 服务器本机引导

```sh
sudo bash scripts/deploy/hz-bootstrap.sh --admin <与 §5 相同的登录名> --expiry 365d --tag server
```

- 签出第一把 Auth Key 并把名为 `<登录名>` 的 User 落库为 Admin；
- Auth Key 必须带至少一个 Tag（`--tag` 可多次，缺省 `server`）：用 Auth Key 注册的
  Node 不归属任何 User，身份就是它的 Tag，Policy 以 `tag:<名字>` 引用。要让某台机器
  归属到 Admin 本人（才能在它上面执行 `hz policy push` 等管理操作），在该机器上用
  `sudo hz login` 交互式登录，登录后它只归属 User、不再带 Tag；
- 首次运行同时签发 Relay Token 回填 `/etc/default/hz-relay` 并重启 hz-relay；
  重复执行只签新 Auth Key，不重签 Relay Token。
- Auth Key 与 Relay Token 都只显示一次，立即保存。

### 6.2 云主机自身作为 Node

bootstrap 里已装好 hzd 并写好 `/etc/default/hzd`（含
`HZD_COORD_ADDR=https://coord.<域名>`、`HZD_RELAY_ADDR=https://relay.<域名>`）：

```sh
sudo hz up --auth-key <Auth Key>
hz status
```

**固定 WireGuard 端口并放行安全组。** hzd 的 UDP 端口缺省随机（`HZD_WG_PORT`
未设置时由内核分配，每次重启都会变）。云主机的安全组只放行 §2.4 列出的端口，
随机端口进不来：打洞信令照常往来（日志有 `punch ack received`），但其他 Node
发往云主机的 WireGuard 握手全部超时（日志反复出现 `HANDSHAKE(REKEY_TIMEOUT)`），
所有 Node 到云主机都只能走 Relayed Path。家宽 Linux 与 macOS Node 在 NAT 后面
靠打洞直连，不需要这一步。

```sh
echo 'HZD_WG_PORT=51820' | sudo tee -a /etc/default/hzd
sudo systemctl restart hzd
ss -lnup | grep ':51820\b'          # 应见 hzd
```

然后在云厂商控制台的安全组里放行 **UDP 51820**（入方向，来源 0.0.0.0/0；如果
本机还开了 ufw/firewalld，也要放行同一端口）。重跑 install.sh 升级时这一行会
原样保留（§7.3）。

验证：在任意一个其他 Node 上执行

```sh
hz status       # 云主机一行应为 Direct Path (IPv4)，Endpoint 是 <公网 IP>:51820
hz netcheck     # 对端列表里云主机为 Direct Path，最近打洞：成功
```

仍是 Relayed Path 时，先在云主机上 `sudo tcpdump -ni any udp port 51820`，再从
其他 Node `hz ping <云主机 Node Name>`：抓不到包说明安全组或本机防火墙仍在拦截；
抓得到包但握手不成，查 hzd 日志。

### 6.3 其他 Linux Node（如家宽后的机器）

```sh
curl -fsSL https://coord.<域名>/install.sh | sudo sh
sudo hz up --auth-key <Auth Key>
```

`install.sh` 看到 Coordination Server 地址是 `https://coord.<域名>` 时，把
`HZD_RELAY_ADDR=https://relay.<域名>` 写入 `/etc/default/hzd`（ADR-0004 的三子域名）。
已经存在的 `HZD_RELAY_ADDR` 重跑安装时原样保留。Relay 不在 `relay.<域名>` 上时，
安装前设置 `HZNET_RELAY_ADDR`（写法见 [install-guide.md](install-guide.md) §6）。
hzd 没有对应的命令行 flag；私有 CA 仍要另写 `HZD_RELAY_CA_PATH`。

### 6.4 macOS Node

```sh
curl -fsSL https://coord.<域名>/install.sh | sudo sh
sudo hz up --auth-key <Auth Key>
```

launchd 不继承 shell 环境变量。`install.sh` 把 `HZD_COORD_ADDR` 与（能确定时）
`HZD_RELAY_ADDR` 写进 `/Library/LaunchDaemons/com.hznet.hzd.plist` 的
`EnvironmentVariables`，再加载服务。已有的 `HZD_RELAY_ADDR` 重跑时保留。
非标准 Relay 地址与私有 CA 见 [install-guide.md](install-guide.md) §6。

macOS 的详细冒烟步骤（utun、路由、launchd、DNS）见
[docs/macos-smoke-test.md](macos-smoke-test.md)。无 Auth Key 时 `sudo hz up`
走交互式登录：打印登录链接 → 浏览器完成 Kanidm OIDC 登录 → Node 获得授权
（FR-2）。Node 接入后用 `hz policy push <file.toml>`（Admin 名下 Node）配置
访问规则，即可按 Policy 互访。

### 6.5 从 v0.1.3 及更早版本升级：无 Tag 的 Auth Key 与 Node

v0.1.4 起签发 Auth Key 必须带 Tag（`hz authkey create`、`hz-coord bootstrap`、
`hz-bootstrap.sh`；服务端也拒绝无 Tag 的签发请求）。此前签发的无 Tag Key 会注册出
既不归属 User、也不带 Tag 的 Node（`hz node list` 里「归属 User」为「无（Tag 注册）」
且「Tags」为「无」），Policy 的任何规则都覆盖不到它：配置了 Policy 后它与所有 Node
互不可达。

兼容处理：已签发的无 Tag Key 在过期或吊销前仍可注册（hz-coord 每次记一条
`node registered with a tagless auth key` 告警日志），已有的此类 Node 照常运行。
建议升级后逐项处理：

1. 找出仍有效的无 Tag Key 并吊销（Key ID 在签发时显示过；找不到时在服务器上查库）：

   ```sh
   sudo sqlite3 /var/lib/hz-coord/hznet.db \
     "SELECT id, datetime(expires_at_unix, 'unixepoch') FROM auth_keys
      WHERE tags = '[]' AND expires_at_unix > strftime('%s', 'now')
        AND (single_use = 0 OR used_at_unix IS NULL);"
   sudo hz authkey revoke <Key ID>
   ```

2. 找出无归属也无 Tag 的 Node：在 Admin 名下的机器上执行 `hz node list`，看「归属 User」
   为「无（Tag 注册）」且「Tags」为「无」的行。按用途二选一：
   - 属于某个人的机器：在该机器上执行 `sudo hz login`，登录后归属到登录的 User，
     Node Name、Node Address 不变；
   - 无人值守的服务器：Admin 签发带 Tag 的新 Key（`sudo hz authkey create --expiry 7d
     --once --tag <名字>`），Admin 先 `hz node delete <Node ID>` 删掉旧记录，再在该机器上
     `sudo hz up --auth-key <新 Key>` 重新注册（Node Address 可能变化）。

## 7. 日常运维

### 7.1 SQLite 备份

在线快照（对运行中的 hz-coord 安全），WAL checkpoint + 完整性校验：

```sh
sudo bash scripts/deploy/backup.sh                    # → /var/backups/hznet/hz-coord-<时间戳>.db
sudo bash scripts/deploy/backup.sh --with-kanidm      # 附带 Kanidm 最近一次在线备份
```

建议 crontab（root）每天 4:00 备份并保留异地拷贝：

```cron
0 4 * * * /bin/bash /path/to/HertzMeshNet/scripts/deploy/backup.sh --with-kanidm >> /var/log/hznet-backup.log 2>&1
```

Kanidm 自身在 `/etc/kanidm/server.toml` 配置了每日 22:00 在线备份
（`/var/backups/kanidm/`，保留 7 份）。

### 7.2 恢复

```sh
sudo systemctl stop hz-coord    # restore.sh 会代停；此处仅示意
sudo bash scripts/deploy/restore.sh --backup /var/backups/hznet/hz-coord-<时间戳>.db
```

旧库自动留存为 `hznet.db.pre-restore.<时间戳>`；恢复前后都做 integrity_check。

### 7.3 升级

服务端（停 → 换二进制 → 启动时自动跑 sqlx 迁移 → 健康检查）：

```sh
sudo bash scripts/deploy/backup.sh          # 升级前先备份（数据库迁移不可回滚）
sudo bash scripts/deploy/upgrade.sh --dist <新 dist 目录>
```

版本协议 N-2（FR-6）：先升服务器，旧 Node 仍可用；Node 升级在各 Node 重新
执行 install.sh（`curl -fsSL https://coord.<域名>/install.sh | sudo sh`，
脚本检测到 hzd 已运行会自动重启升级，macOS 侧 plist 同样保留）。回滚用旧
dist 再跑一次 upgrade.sh（仅二进制回退；若新版本已执行了数据库迁移，需从
备份恢复数据库）。

### 7.4 日志

```sh
journalctl -u hz-coord -f          # gRPC/注册/Network Map（tracing，英文）
journalctl -u hz-relay -f          # Relay 转发与限速
journalctl -u kanidm -f            # IdP（OIDC 登录问题先看这里）
journalctl -u nginx -f             # SNI 分流与反代
tail -f /Library/Logs/hzd.log      # macOS Node
```

### 7.5 指标（Prometheus）

coord `:9100`、relay `:9101` 只绑 127.0.0.1。Prometheus 跑在同机时，把
`packaging/deploy/prometheus/scrape.yml` 的片段并入 `prometheus.yml`。异地
抓取走 SSH 隧道（`ssh -L 9100:127.0.0.1:9100 ...`），不要把端口开进安全组。
关键指标：在线 Node 数、按 Node 的 Relay 流量与限速丢弃、打洞成功率（FR-12）。

### 7.6 健康检查

只读，不重启、不改文件。在云主机上：

```sh
sudo bash scripts/deploy/healthcheck.sh --domain <域名>
```

省略 `--domain` 时从 `/etc/default/hz-coord` 的 `--public-url`（其次 `/etc/default/hzd` 的 `HZD_COORD_ADDR`）推导，主机名须为 `coord.<域名>`。

逐项打印 `PASS` / `FAIL` / `SKIP`（供以后 Admin Console 健康页复用）：Coordination Server 本机 `http://127.0.0.1:8080/healthz`、Relay 的 TLS（先 `127.0.0.1:443` 上的 SNI `relay.<域名>`，不通再看 `:8444`）、Kanidm `https://auth.<域名>/status`（经本机 443，避免绕回公网 IP）、`nginx -t`（未安装 nginx 则 SKIP）、`/etc/hznet/tls/{coord,relay,auth}/fullchain.pem` 是否在 `--cert-days`（默认 14）天内到期、三条 DNS A 记录（有 `getent` 或 `python3` 才查；三者不一致也算 FAIL）。任一 FAIL 则退出码非零。

## 8. 与第三方 TUN 类网络工具共存

Node 侧的现象、自检与配置方法见 [安装手册第 10 节](install-guide.md#10-与第三方-tun-类网络工具共存)，这里只列运维要点：

- hzd 只把 HzNet 地址段路由进自己的 TUN，外层流量（WireGuard / STUN / 到 coord 与 relay 的连接）绑定物理出口网卡（FR-7）。
- 外层域名解析：系统 DNS 返回 `198.18.0.0/15` 假地址时，hzd 经物理网卡改问引导 DNS（`HZD_BOOTSTRAP_DNS`，缺省为系统 DHCP DNS 再退到公共 DNS），并缓存最近一次有效结果（#23）。内网部署若公共 DNS 不可达，请在 Node 的 hzd 环境里显式配置 `HZD_BOOTSTRAP_DNS`。
- HzNet 路由被删除或被同前缀路由占用时，hzd 在 10 秒内自动恢复（#24）。
- 在第三方工具里**不要排除与 HzNet 完全相同的前缀**，应排除更宽的范围；只加"直连"规则不够（直连流量从物理网卡发出，到不了 HzNet）。
- macOS 上基于 Network Extension 的工具强制接管路由时，路由表不起作用，只能在该工具里排除 HzNet 地址段（spec 已知限制）。

## 9. 与占用 100.64.0.0/10 的组网工具同时运行（如 Tailscale）

背景：CGNAT 段 `100.64.0.0/10` 常被其他组网工具整段路由进自己的隧道；HzNet
的默认 Node Address 段 `100.96.0.0/16` 落在其中（ADR-0003 当年特意只取 /16，
避开云厂商在 `100.100.0.0/16` 的内网 DNS/元数据）。两者同时运行时，若第三方
工具路由整段 `100.64.0.0/10`，它会抢走 HzNet 的 `100.96.0.0/16`，发往 Node
Address 的流量进错隧道。

处理顺序（推荐）：

1. **优先在第三方工具侧收窄/排除**：把它路由的段从 `100.64.0.0/10` 收窄到
   不与 `100.96.0.0/16` 重叠的子段，或在其排除列表里去掉 `100.96.0.0/16`。
   多数此类工具支持自定义网段。
2. **或给 HzNet 改段**（`--cidr`，#20 已实现）。`hz-coord bootstrap` 与
   `hz-coord serve` 均支持 `--cidr <CIDR>`（至少 /25）与可重复的
   `--reserve <IP>`：首次初始化时固化进 SQLite 的 meta 表，之后不带 flag
   重启一律沿用固化值。改段语义：**库中已有 Node 时拒绝改段**（错误信息会
   给出处置指引）——旧段地址已分布在所有 Network Map 与各 Node 本地；需要
   改段时备份 SQLite、删除库文件、以新段 `bootstrap --cidr` 重新初始化并
   重新注册全部 Node。**首次部署前选定与其他工具不冲突的段**，远比事后改段
   便宜。Node 侧无需配置：注册/登录响应携带生效段与段内推导的 DNS 地址
   （网络基址低位置 53，默认段即规格 A2 的 100.96.0.53），hzd 据此配置 TUN
   路由与本地 DNS；`HZD_V4_CIDR` 仅作显式覆盖，与服务端失配时会告警。

## 10. 验收清单（G2：需在真实主机上执行）

| AC | 项目 | 依据 |
|---|---|---|
| AC1 | 三个子域名共用 TCP 443，安全组开放 UDP 3478 | §1 端口表、§2.4；`ss -lntp \| grep -E ':443\b'` 只应见 nginx，`ss -lnup \| grep 3478` 见 hz-relay |
| AC2 | Kanidm 已配置 OIDC 客户端与 `hznet_admins` 组 | §5 输出的 client_id/issuer；`kanidm group get hznet_admins` |
| AC3 | ≥1 macOS + 1 家宽 Linux + 1 云主机组成 HzNet 并按 Policy 互访 | 下面三步 |
| AC4 | 手册覆盖 bootstrap、SQLite 备份与恢复、升级 | §6、§7.1-§7.3 |
| AC5 | 第三方 TUN 工具共存规则与 100.64/10 冲突说明 | §8、§9 |

AC3 的三步（需要你自己的三台机器；Policy 以"dev 组可访问 db Tag 的 5432"
为例）：

1. 三台机器分别 `hz up`（云主机按 §6.2、Linux 按 §6.3、macOS 按 §6.4），
   `hz status` 三台都在线；
2. 云主机（Admin 名下 Node）写 Policy 并推送：
   `hz policy push policy.toml`（规则形如 `group:dev → tag:db:5432`）；
3. 互访验证：macOS `ping db-1.hznet.internal` 通、`psql -h db-1.hznet.internal -p 5432` 通；
   非 dev 成员 `hz status` 里看不到 `db-1`；`hz ping db-1` 报告 Direct/Relayed Path。
   家宽 Linux 与 macOS 之间同样按 Policy 验证一遍。

## 11. 故障排查

| 症状 | 排查 |
|---|---|
| `hz up` 报连接 Coordination Server 失败 | `curl -fsS https://coord.<域名>/healthz`；不通看 `nginx -t`、`journalctl -u nginx`（SNI 分流按域名匹配，DNS 必须先生效）；证书过期看 §3 |
| hz-coord 起不来，日志提 OIDC 发现文档 | OIDC 在启动时同步拉发现文档（`OidcClient::discover`）：确认 kanidm 已运行、正式证书已装、`/etc/default/hz-coord` 里 `--oidc-issuer` 指向 `https://auth.<域名>/oauth2/openid/hznet-coord` |
| 交互式登录回调 404/被拒 | Kanidm 侧回调必须精确等于 `--oidc-redirect-uri`（`https://coord.<域名>/oidc/callback`）；重跑 §5 会重新 PATCH 回调 |
| 打开 `https://coord.<域名>/admin/` 是 nginx 404 或默认页 | 先 `curl -sI http://127.0.0.1:8080/admin/`，预期 307 到 `/admin/login`。本机通、公网不通：`nginx -t`，确认 `/etc/nginx/sites-enabled/hznet` 的 `location /` 含 `proxy_pass http://127.0.0.1:8080`，然后按 §5.1 重装模板并 `systemctl reload nginx`。`journalctl -u nginx` 看 SNI 是否把 coord 送进了 8443 |
| `/admin/login` 显示「未配置交互式登录」 | `/etc/default/hz-coord` 缺 `--oidc-*`，或 hz-coord 启动时没拉到发现文档。重跑 §5；`journalctl -u hz-coord` 与 `journalctl -u kanidm` |
| Kanidm 报 `redirect_uri` 不匹配 | 必须精确等于 `https://coord.<域名>/admin/oidc/callback`，与 Node 的 `/oidc/callback` 是同一客户端上的两条，不要新建第二个 OAuth2 客户端。重跑 §5 |
| 登录页写「无权进入」 | 该账号不在 `hznet_admins`。`kanidm group get-members hznet_admins`，然后 `kanidm group add-members hznet_admins <某人>`。只有组成员会拿到 `hz_admin` cookie |
| 回到 `/admin/` 后接口仍是 401，或重启后又要登录 | 开发者工具里看有没有 `hz_admin`。没有：回调必须是 https（https 回调才加 `Secure`），`Path` 必须是 `/admin`（只写成 `/admin/` 会漏掉 `/admin/api`）。有 cookie 仍 401：会话在 hz-coord 内存里，`systemctl restart hz-coord` 会清掉，重新打开 `/admin/` |
| 打开登录链接后 Kanidm 登录页 404（如 `/ui/login/begin`），或换无痕窗口才能登录 | 证书仍是一张覆盖三个子域名的多 SAN 证书，浏览器把 auth 的请求合并进了 coord 的连接：按 §3「已部署环境的迁移」换成单域名证书并更新 nginx 配置，然后重启浏览器 |
| `hz login` 打印的登录链接是 `http://127.0.0.1:…` | hz-coord 低于 v0.1.4，或 `/etc/default/hz-coord` 缺 `--public-url https://coord.<域名>`（v0.1.4 起登录链接按它拼接，缺省时取 `--oidc-redirect-uri` 的主机） |
| 配置 Policy 后某台 Node 与所有 Node 都不通，`hz node list` 显示「归属 User：无（Tag 注册）」「Tags：无」 | 它是用 v0.1.4 之前签发的无 Tag Auth Key 注册的，Policy 覆盖不到；按 §6.5 处置 |
| Node 注册成功但彼此不通 | `hz status` 看路径；Relayed Path 不通查 `journalctl -u hz-relay` 与 `/etc/default/hz-relay` 的 token 是否仍为 `@RELAY_TOKEN@`（重跑 §6.1）；直连不成立时确认安全组放行 UDP 3478（STUN）；只有到云主机这一个对端不直连时，按 §6.2 固定 `HZD_WG_PORT` 并放行 UDP 51820；先跑 `hz netcheck` 看 UDP 外发与上报的 Endpoint |
| `*.hznet.internal` 解析失败 | 本机是否运行第三方 TUN 类工具（§8）；macOS 看 `/etc/resolver/hznet.internal`；`hzd` 停止时系统普通 DNS 应不受影响（FR-5 AC） |
| STUN 发现的 Endpoint 是第三方工具的出口 | hzd 外层流量应绑物理网卡（FR-7）；确认没有把 hzd 的流量导入第三方 TUN 类网络工具的虚拟网卡 |
| hzd 日志 `stun query failed server=198.18.x.x` 或连 coord/relay 失败 | 系统 DNS 被第三方工具接管：确认日志出现"改用引导 DNS"；引导 DNS 不可达时配置 `HZD_BOOTSTRAP_DNS`（§8） |
| `hz status` 提示"流量被其他隧道接管"/"名字解析被接管" | 按安装手册第 10.4 节在对应工具中排除 HzNet 地址段、把域名后缀交给 HzNet 本地 DNS；macOS 强制接管路由的限制见 §8 |
| 证书续期未生效 | `crontab -l` 有 acme.sh 任务；`~/.acme.sh/acme.sh --list` 应列出三个子域名各一张；手工 `--force`；各证书的 reloadcmd 分别 reload nginx、重启 hz-relay、重启 kanidm |
| 恢复后数据异常 | `restore.sh` 的 `.pre-restore.*` 旧库仍在；WAL 已随恢复清理，勿手工混拷 `hznet.db-wal` |
