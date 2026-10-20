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
                      │
        coord.<域名> ─┤→ 127.0.0.1:8443  nginx https（终止 TLS）
                      │      ├─ /hz.v1.Coord/*  ─→ grpc(h2c) → 127.0.0.1:50051  hz-coord（gRPC 明文）
                      │      └─ /install.sh /dl/ /oidc/ /healthz ─→ 127.0.0.1:8080  hz-coord（HTTP 明文）
        relay.<域名> ─┤→ 127.0.0.1:8444  hz-relay（自带 TLS 终止）
        auth.<域名>  ─┤→ 127.0.0.1:8445  kanidmd（自带 TLS 终止）

        127.0.0.1:9100  hz-coord /metrics      127.0.0.1:9101  hz-relay /metrics
```

| 端口 | 协议 | 归属 | 用途 |
|---|---|---|---|
| 443 | TCP | nginx stream | 三个子域名按 SNI 分流（FR-6/FR-9/ADR-0004） |
| 80 | TCP | nginx http | ACME HTTP-01 验证、跳转 https |
| 3478 | UDP | hz-relay | STUN 公网 Endpoint 发现（FR-8） |
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
4. **安全组**放行：TCP 443、TCP 80、UDP 3478（其余端口一律不开；9100/9101 只绑
   127.0.0.1，不入安全组）。
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

- HTTP-01 走 nginx 80 端口 webroot；一张证书三个 SAN（coord/relay/auth）。
- 安装到 `/etc/hznet/tls/{coord,relay,auth}/`；续期 reload：nginx reload +
  重启 hz-relay / kanidm（它们只在启动时读证书）。
- 续期由 acme.sh 自带的定时任务自动完成（`crontab -l` 可见），无需人工干预；
  强制续期加 `--force`。
- 测试环境可重生成占位证书：`sudo bash scripts/deploy/certs.sh --domain <域名> --self-signed`。

自检：

```sh
curl -fsS https://coord.<域名>/healthz   # 预期 ok
curl -fsS https://auth.<域名>/status     # 预期 true（kanidm 已启动）
```

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

此时 coord 已可对公网提供 `/install.sh` 与 `/dl/`，但登录与 Relay 还不可用，
继续 §5、§6。

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
   `https://coord.<域名>/oidc/callback`，scopes openid/profile/groups）；
4. 把 `--oidc-*` 连同 client secret 写进 `/etc/default/hz-coord`（权限 0600）
   并重启 hz-coord，等待 `/healthz` 恢复。

结束打印一行 JSON（**口令与 secret 仅此一次显示，立即保存到密码管理器**）：

```json
{"client_id":"hznet-coord","client_secret":"...","issuer":"https://auth.<域名>/oauth2/openid/hznet-coord","redirect_uri":"https://coord.<域名>/oidc/callback","admin_name":"...","admin_password":"..."}
```

`hznet_admins` 的成员即 HzNet Admin（FR-11，经 OIDC groups claim 传给
Coordination Server）。此后加管理员就是往 Kanidm 组里加人：

```sh
kanidm group add-members hznet_admins <某人>
```

## 6. bootstrap 与首个 Node 接入（G2）

> Node 侧的完整安装、注册、验证、升级与卸载步骤单独成篇：[install-guide.md](install-guide.md)。本节只讲服务器侧的 bootstrap 与首台验收。

### 6.1 服务器本机引导

```sh
sudo bash scripts/deploy/hz-bootstrap.sh --admin <与 §5 相同的登录名> --expiry 365d
```

- 签出第一把 Auth Key 并把名为 `<登录名>` 的 User 落库为 Admin；
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

### 6.3 其他 Linux Node（如家宽后的机器）

```sh
curl -fsSL https://coord.<域名>/install.sh | sudo sh
echo 'HZD_RELAY_ADDR=https://relay.<域名>' | sudo tee -a /etc/default/hzd
sudo systemctl restart hzd
sudo hz up --auth-key <Auth Key>
```

> 第二行是必须的：install.sh（#17）目前只写 `HZD_COORD_ADDR`；Relay 地址
> 只有环境变量 `HZD_RELAY_ADDR` 一个入口（无 CLI flag）。

### 6.4 macOS Node

```sh
curl -fsSL https://coord.<域名>/install.sh | sudo sh
```

launchd 不继承 shell 环境变量，且 install.sh 生成的 plist 只带
`HZD_COORD_ADDR`，需要手工补 Relay 地址（`/Library/LaunchDaemons/com.hznet.hzd.plist`
的 `EnvironmentVariables` 字典里加一项；之后重跑 install.sh 升级会保留这一项）：

```sh
sudo /usr/libexec/PlistBuddy -c 'Add :EnvironmentVariables:HZD_RELAY_ADDR string https://relay.<域名>' \
  /Library/LaunchDaemons/com.hznet.hzd.plist
sudo launchctl bootout system/com.hznet.hzd 2>/dev/null || true
# 旧 hzd 退出前要先恢复 DNS 配置，等它从 launchd 卸载完再加载，否则 bootstrap 报 I/O 错误
while sudo launchctl print system/com.hznet.hzd >/dev/null 2>&1; do sleep 1; done
sudo launchctl bootstrap system /Library/LaunchDaemons/com.hznet.hzd.plist
sudo hz up --auth-key <Auth Key>
```

macOS 的详细冒烟步骤（utun、路由、launchd、DNS）见
[docs/macos-smoke-test.md](macos-smoke-test.md)。无 Auth Key 时 `sudo hz up`
走交互式登录：打印登录链接 → 浏览器完成 Kanidm OIDC 登录 → Node 获得授权
（FR-2）。Node 接入后用 `hz policy push <file.toml>`（Admin 名下 Node）配置
访问规则，即可按 Policy 互访。

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
| Node 注册成功但彼此不通 | `hz status` 看路径；Relayed Path 不通查 `journalctl -u hz-relay` 与 `/etc/default/hz-relay` 的 token 是否仍为 `@RELAY_TOKEN@`（重跑 §6.1）；直连不成立时确认安全组放行 UDP 3478（STUN） |
| `*.hznet.internal` 解析失败 | 本机是否运行第三方 TUN 类工具（§8）；macOS 看 `/etc/resolver/hznet.internal`；`hzd` 停止时系统普通 DNS 应不受影响（FR-5 AC） |
| STUN 发现的 Endpoint 是第三方工具的出口 | hzd 外层流量应绑物理网卡（FR-7）；确认没有把 hzd 的流量导入第三方 TUN 类网络工具的虚拟网卡 |
| hzd 日志 `stun query failed server=198.18.x.x` 或连 coord/relay 失败 | 系统 DNS 被第三方工具接管：确认日志出现"改用引导 DNS"；引导 DNS 不可达时配置 `HZD_BOOTSTRAP_DNS`（§8） |
| `hz status` 提示"流量被其他隧道接管"/"名字解析被接管" | 按安装手册第 10.4 节在对应工具中排除 HzNet 地址段、把域名后缀交给 HzNet 本地 DNS；macOS 强制接管路由的限制见 §8 |
| 证书续期未生效 | `crontab -l` 有 acme.sh 任务；`~/.acme.sh/acme.sh --list`；手工 `--force`；reloadcmd 会 reload nginx 并重启 hz-relay/kanidm |
| 恢复后数据异常 | `restore.sh` 的 `.pre-restore.*` 旧库仍在；WAL 已随恢复清理，勿手工混拷 `hznet.db-wal` |
