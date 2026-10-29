# HertzMeshNet MVP 规格说明

> 状态：已完成 · 2026-10-19 发布于 [v0.1.1](https://github.com/yarneer/HertzMeshNet/releases/tag/v0.1.1)（草案 2026-10-18；跟踪 issue [#1](https://github.com/yarneer/HertzMeshNet/issues/1)）
> 术语以 [GLOSSARY.md](../GLOSSARY.md) 为准，关键决策见 [docs/adr/](adr/)。本文只描述 MVP 要做到什么、怎样算做完，不规定内部实现。

## 1. 目标

让一个组织（几百个 Node、多个 User）在自己的云主机上部署一套 HzNet：分散在各种 NAT 后面的 Linux/macOS 机器能彼此按 Node Address 或 Node Name 访问，能直连时直连，不能直连时经 Relay 中转，访问范围受 Policy 约束。

项目以学习驱动，但以"本组织真实可用"作为验收标准。

### 非目标（MVP 不做）

- 兼容官方 Tailscale 客户端或协议（[ADR-0001](adr/0001-full-stack-own-protocol.md)）
- 多租户、一次部署多个 HzNet
- 子网路由、出口节点、管理 Web 界面、密钥轮换 UI（第二阶段）
- Windows（计划于 v0.5，见 [macos-client-spec §11](macos-client-spec.md)）、iOS、Android、macOS Network Extension（注：iOS 同一时间只允许一个隧道类网络配置处于激活状态，届时 HzNet 无法与其他第三方 TUN 类网络工具同时开启）
- Coordination Server 高可用、多地域 Relay
- 与 Kanidm 的实时联动（User 被禁用后靠有效期兜底）、从 IdP 同步 Group
- Node 自动升级

## 2. 系统组成与部署

| 组件 | 形态 | 部署位置 |
|---|---|---|
| Coordination Server（`hz-coord`） | 单实例，SQLite 存储 | 大陆云主机，`coord.<域名>:443` |
| Relay（`hz-relay`） | 单实例，独立二进制 | 同一台云主机，`relay.<域名>:443`，STUN 用 UDP 3478 |
| Kanidm | IdP，标准 OIDC | 同一台云主机，`auth.<域名>:443`，必须能从公网访问 |
| `hzd` | Node 上以 root 运行的守护进程 | Linux（systemd）、macOS（launchd） |
| `hz` | 普通权限命令行工具，经本地 Unix socket 与 `hzd` 通信 | 同上 |

- 三个公网服务都用已备案域名，按子域名区分，共用 TCP 443（[ADR-0004](adr/0004-mainland-china-deployment.md)）。
- 服务端以 musl 静态二进制配合 systemd 运行，不用容器。
- Coordination Server 只在控制路径上，不转发 Node 之间的业务流量。

## 3. 功能需求

每条需求都附有验收标准（AC）。

### FR-1 Node 注册：Auth Key

- Admin 可以签发 Auth Key，属性包括：必填的过期时间、一次性或可重复使用、可选的预绑定 Tag。
- Auth Key 明文只在签发时显示一次，服务端只保存哈希。
- `hz up --auth-key <key>` 注册 Node。用带 Tag 的 Auth Key 注册的 Node 获得这些 Tag，不归属任何 User。
- **AC**：一次性 Key 第二次使用被拒绝；过期 Key 被拒绝；用带 Tag 的 Key 注册的 Node 在 `hz status` 中显示为带 Tag、无 User。

### FR-2 Node 注册：交互式登录

- `hz up`（不带 Auth Key）时，`hzd` 向 Coordination Server 申请一次性登录链接并打印出来。User 在任意设备的浏览器中完成 Kanidm 的 OIDC 登录，回调落在 Coordination Server，Node 随即获得授权。整个系统里只有 Coordination Server 是 OIDC 客户端。
- 登录链接有短有效期，并且只能使用一次。
- **AC**：在没有浏览器的服务器上执行 `hz up`，复制链接到笔记本上登录，服务器即可加入 HzNet；Node 上不保存任何 IdP 凭证。

### FR-3 身份、密钥与有效期

- 每个 Node 持有一把长期的 Machine Key 和一把数据面用的 Node Key（[ADR-0005](adr/0005-machine-key-and-node-key.md)）。
- Node 向 Coordination Server 认证的方式是用 Machine Key 对挑战值签名，不使用 mTLS。
- 归属 User 的 Node 有效期默认 90 天（可配置），到期后需要重新登录。重新登录会轮换 Node Key，但 Node 的身份、Node Address 和 Node Name 不变。
- 带 Tag 的 Node 不过期，只能由 Admin 吊销。
- 被吊销或已过期的 Node 会从所有 Network Map 中移除。
- **AC**：把有效期调成 1 分钟，到期后该 Node 与其他 Node 无法通信；它重新登录后 Node Address 不变，且能恢复通信。

### FR-4 Node Address 与 Node Name

- IPv4 地址段可配置，默认 `100.96.0.0/16`，`hzd` 只把这个段路由进 TUN（[ADR-0003](adr/0003-node-address-range.md)）。每个 Node 还会分配一个 ULA IPv6 地址。
- Node Address 在 Node 的生命周期内保持稳定。
- Node Name 在 HzNet 内唯一，默认取主机名并做规范化；重名时自动加后缀 `-2`、`-3`……Admin 可以改任何 Node 的名字，User 可以改自己名下 Node 的名字。
- **AC**：在阿里云主机上运行 `hzd` 后，主机的内网 DNS（`100.100.2.136` 等）和元数据服务仍然可用。

### FR-5 网内名字解析

- 在 Node 上用 `<Node Name>.hznet.internal` 可以解析到对端的 Node Address（后缀可配置）。
- Linux 上通过 systemd-resolved 做分域 DNS，macOS 上通过 `/etc/resolver/` 实现，只接管 HzNet 的域名后缀，不影响系统其他 DNS 解析。
- **AC**：`ping db-1.hznet.internal` 能通；`hzd` 停止后，系统的普通 DNS 解析不受影响。
- 第三方 TUN 类网络工具可能接管系统 DNS，导致 `*.hznet.internal` 查询不经过 `hzd`。运维手册须给出与第三方 TUN 类网络工具共存的配置示例。

### FR-6 Network Map 下发

- Node 与 Coordination Server 之间保持一条 gRPC 长连接双向流（TLS 443）。Coordination Server 通过它推送 Network Map 的全量与增量更新。
- 下发给某个 Node 的 Network Map 只包含 Policy 允许它访问、或允许访问它的那些 Node（[ADR-0006](adr/0006-network-map-filtered-by-policy.md)）。
- Node 在本地缓存最近一次收到的 Network Map。Coordination Server 不可用时，已连接的 Node 之间照常通信；Coordination Server 恢复后，Node 自动重连。
- 每个 Node 上报自己的协议版本号。Coordination Server 至少兼容最近 N-2 个版本，更旧的 Node 会被拒绝，并收到明确的升级提示。
- **AC**：停掉 Coordination Server 10 分钟，期间两个已连接 Node 之间的 SSH 会话不断；修改 Policy 后，受影响的 Node 在 5 秒内收到新的 Network Map。

### FR-7 数据面

- `hzd` 在用户态运行 WireGuard（`boringtun`），通过 TUN（Linux）或 utun（macOS）收发流量（[ADR-0002](adr/0002-userspace-wireguard.md)）。
- 打洞用的 UDP socket 和 WireGuard 收发数据用的是同一个 socket。
- **与其他接管默认路由的网络工具共存**：`hzd` 自身的隧道外层流量（WireGuard/打洞 UDP、STUN、到 Coordination Server 与 Relay 的连接）绑定到当前的物理出口网卡（macOS `IP_BOUND_IF`，Linux `SO_BINDTODEVICE` 或 fwmark 策略路由），不进入第三方 TUN 类网络工具的虚拟网卡；物理出口变化时随之重新绑定。
- **AC**：本机同时运行一个接管默认路由的第三方 TUN 类网络工具时，`hzd` 的外层流量仍从物理网卡发出，STUN 发现的公网 Endpoint 是本机真实出口地址，HzNet 连通不受影响；发往 Node Address 的流量走 HzNet 的 TUN，而不进入第三方工具的虚拟网卡。

### FR-8 NAT 穿透与路径选择

- Node 通过 STUN（Relay 主机上的 UDP 3478）发现自己的公网 Endpoint，同时收集内网 Endpoint 和 IPv6 Endpoint，上报给 Coordination Server。
- 打洞所需的实时 Endpoint 协商通过 Relay 通道传递，并用 Node Key 做端到端加密，Coordination Server 不参与。
- 两个 Node 一开始先走 Relayed Path，同时尝试打洞。打洞成功后升级到 Direct Path；直连失效后自动退回 Relayed Path。**IPv6 直连优先尝试。**
- 本机网络变化（换 Wi-Fi、IP 变动、休眠后唤醒）后，Node 能自动重新发现 Endpoint 并恢复连接。
- **AC**：在测试拓扑（见第 5 节）中，下列组合都满足要求：
  - 两端都是锥形 NAT：建立 Direct Path
  - 一端是对称型 NAT、另一端是锥形 NAT：尽力尝试直连，失败时稳定走 Relayed Path
  - 两端都是对称型 NAT：走 Relayed Path
  - 模拟网络切换后，30 秒内恢复连通
  - 一端本机运行着接管默认路由的第三方 TUN 类网络工具时，上述结果不变

### FR-9 Relay

- Relay 通过 TCP 443 上的 TLS 提供服务，按 Node Key 寻址并转发已经加密的数据包。它看不到明文，也看不到打洞信令的内容。
- 只有已注册且有效的 Node 才能连接 Relay，Relay 向 Coordination Server 校验 Node 的身份。
- 每个 Node 的 Relay 流量有限速，默认 10 Mbps、可配置；Relay 按 Node 统计流量。
- **AC**：未注册的客户端无法通过 Relay 收发数据；单个 Node 的 Relay 吞吐不超过配置的上限。

### FR-10 Policy

- Policy 是一份 TOML 文件，内容包括 Group 定义（由 User 组成）和访问规则。每条规则的形式是"主体（User / Group / Tag）→ 目标（Tag / User 的 Node）: 端口"，规则之外的流量默认拒绝。
- Admin 用 `hz policy push <file>` 整份替换 Policy。Coordination Server 先校验（引用的 User、Group、Tag 必须存在或语法合法），校验失败就拒绝替换；它会保留历史版本，并支持 `hz policy get` 和回滚到指定版本。
- Policy 一方面决定 Network Map 中包含哪些 Node，另一方面由**目标 Node 的 `hzd` 对入站流量做过滤**（见第 7 节假设 A1）。
- **AC**：Policy 只允许 `group:dev → tag:db:5432` 时，dev 组成员能连 `db-1:5432`，连 `db-1:22` 会被拒绝，非 dev 组成员的 Network Map 中看不到 `db-1`。

### FR-11 Admin 与管理操作

- Kanidm 中 `hznet_admins` 组的成员（通过 OIDC groups claim 传给 Coordination Server）就是 Admin。
- 第一个 Admin 和第一把 Auth Key 在 Coordination Server 本机上用 `hz-coord` 的 bootstrap 子命令创建。
- 远程管理操作通过 `hz` 发起，前提是所在的 Node 归属一个 Admin（见第 7 节假设 A3）。可执行的操作包括：签发和吊销 Auth Key，列出、改名、删除、吊销 Node，推送和回滚 Policy。
- 普通 User 只能查看、改名、删除自己名下的 Node。
- **AC**：普通 User 执行 `hz authkey create` 会被拒绝；从 `hznet_admins` 中移除某人后，该 User 下次重新登录时失去 Admin 权限。

### FR-12 可观测性

- `hz status` 列出 Network Map 中每个对端的 Node Name、Node Address、当前路径（Direct Path 或 Relayed Path）、正在使用的 Endpoint 和最近一次握手时间。
- `hz ping <node>` 报告往返时延，以及这次走的是哪条路径。
- `hz-coord` 和 `hz-relay` 用 `tracing` 输出结构化日志，并暴露 Prometheus `/metrics`。指标至少包括在线 Node 数、按 Node 统计的 Relay 流量、**打洞成功率**。

### FR-13 分发

- Coordination Server 提供安装脚本 `https://coord.<域名>/install.sh`，按平台下载对应的 `hzd` 和 `hz`，并注册系统服务。
- 支持的平台：Linux x86_64 / aarch64，macOS arm64。

## 4. 非功能需求

- **规模**：单个 HzNet 不超过 500 个 Node，单实例 Coordination Server 和 SQLite 足以承载。
- **安全**：
  - Auth Key 只保存哈希
  - Node 私钥只存在 Node 本地，私钥文件权限设为 0600，只有 root 可读
  - 所有控制流量都走 TLS
  - Relay 和 Coordination Server 都看不到业务数据的明文
- **兼容**：协议的版本策略是 N-2。存储通过 `sqlx` 访问，以后迁移到 PostgreSQL 时只需改连接与方言，不需要重写。

## 5. 测试策略

- 单元测试和集成测试随代码一起写，CI 中运行 `fmt`、`clippy`、`test`。
- **NAT 测试拓扑**：在 Linux 上用 network namespace 加 nftables 搭建。拓扑包括一个模拟公网的 namespace（运行 Coordination Server 和 Relay），以及若干放在完全锥形、端口受限、对称型 NAT 后面的 Node namespace。它负责在 CI 中自动验证 FR-7 与 FR-8 的验收标准，与 MVP 同期建设。拓扑需提供"Node namespace 内额外运行一个接管默认路由的第三方 TUN"的场景，用于验证与其他网络工具共存。
- macOS 只做手工冒烟测试：注册、直连、Relay、名字解析。

## 6. 里程碑

| 里程碑 | 可演示内容 |
|---|---|
| M1 局域网连通 | 两台 Linux Node 用 Auth Key 注册，在同一局域网内通过 Node Address 互相 ping 通 |
| M2 跨 NAT | 在 NAT 测试拓扑中，经 Relay 可以通信，满足条件时能升级为直连 |
| M3 可控 | 交互式登录、Policy、Admin、名字解析都可用 |
| M4 可交付 | macOS 支持、可观测性、安装脚本、在云主机上完成真实部署 |

## 7. 本规格补充的约定

以下几项在 grilling 中没有逐条讨论，由本规格补充，并已于 2026-10-18 确认采纳：

- **A1 Policy 在目标 Node 上执行**：仅靠 Network Map 过滤做不到端口级控制，所以由目标 Node 的 `hzd` 按 Policy 过滤入站流量，源端不做限制。
- **A2 DNS 解析器地址**：`hzd` 在一个保留地址 `100.96.0.53` 上本地应答 DNS 请求。这个地址不分配给任何 Node。不沿用 Tailscale 的 `100.100.100.100`，因为它落在阿里云的 `100.100.0.0/16` 内。
- **A3 远程管理的认证方式**：`hz` 发起的管理操作，以所在 Node 的归属 User 作为操作者；带 Tag 的 Node 不能执行管理操作。
- **A4 Node 本地状态**：Machine Key、Node Key 和 Network Map 缓存存放在 `/var/lib/hzd/`（Linux）和 `/Library/Application Support/hzd/`（macOS）。

## 8. 已知限制

- **macOS 上与"强制接管路由"的 Network Extension 类工具共存**：此类工具开启后，系统按其规则转发，路由表中 HzNet 更具体的路由不起作用，发往 Node Address 的流量会进入对方的隧道（v0.1.1 实测）。HzNet 无法单方面绕过，只能在对方工具中排除 HzNet 地址段（且不得排除与 HzNet 完全相同的前缀，否则其同前缀路由会顶掉 HzNet 的路由）。`hz status` 会检测并提示这种冲突（#25），配置方法见安装手册第 10 节。

