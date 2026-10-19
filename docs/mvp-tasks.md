# HertzMeshNet MVP 实现任务

> **已取代**：本文是最早的按层拆分（T01–T20），实际实现改按纵向切片进行，见 GitHub issue [#2](https://github.com/yarneer/HertzMeshNet/issues/2)–[#18](https://github.com/yarneer/HertzMeshNet/issues/18)（均为 [#1](https://github.com/yarneer/HertzMeshNet/issues/1) 的 sub-issue），已全部完成并随 v0.1.1 发布。下文仅作历史记录保留。

> 依据 [mvp-spec.md](mvp-spec.md)。每张任务都是一个可以独立合并、可以验证的切片。"依赖"列出必须先完成的任务。
> 关键路径：T01 → T02 → T04 → T05 → T07 → T08 → T10 → T11 → T12。

## 依赖总览

```
T01 ─┬─ T02 ─┐
     ├─ T03 ─┼─ T04 ─ T05 ─ T07 ─ T08 ─┬─ T10 ─ T11 ─┬─ T12
     └─ T06 ─┘                 │       │      ↑      ├─ T17 (macOS)
                               └─ T09 ─┴──────┘      └─ T18 (可观测)
                    T05 ─ T13 ─ T15
                    T08 + T13 ─ T14
                    T08 ─ T16
                    T15 + T17 + T18 ─ T19 ─ T20
```

## M1 局域网连通

### T01 Workspace 骨架与 CI
- 创建 Cargo workspace，包含 `hz-proto`、`hz-coord`、`hz-relay`、`hzd`、`hz`、`hz-core`
- 配置 GitHub Actions，运行 `fmt`、`clippy -D warnings`、`test`
- **完成标准**：空 crate 全部能编译，CI 通过
- 依赖：无

### T02 控制协议 v1（`hz-proto`）
- 用 protobuf 定义以下内容：挑战认证、注册（Auth Key / 交互式）、Network Map 双向流（全量 + 增量）、Endpoint 上报、协议版本号、管理操作
- **完成标准**：tonic 代码生成通过；版本号字段与 N-2 兼容规则写入协议文档注释
- 依赖：T01

### T03 Coordination Server 存储
- 用 SQLite 和 `sqlx` 迁移脚本建表，覆盖 User、Node（含 Machine Key、Node Key、Node Address、Node Name、Tag、有效期）、Auth Key（哈希）、Policy 版本
- 实现 Node Address 分配器：可配置地址段，默认 `100.96.0.0/16`，保留 `100.96.0.53`；以及 ULA IPv6 地址分配
- 实现 Node Name 规范化与去重（加 `-2` 后缀）
- **完成标准**：分配器、去重逻辑有单元测试；迁移可以重复执行
- 依赖：T01

### T04 Coordination Server gRPC 与 Machine Key 认证
- 基于 tonic 的服务端，跑在 TLS 上
- 实现 Machine Key 的挑战签名认证
- 实现协议版本检查，太旧的版本会被拒绝并返回升级提示
- **完成标准**：集成测试覆盖三种情况：认证成功、签名错误被拒绝、版本过旧被拒绝
- 依赖：T02、T03

### T06 `hzd` / `hz` 骨架
- `hzd` 作为守护进程运行，负责本地状态目录（A4）、生成和持久化 Machine Key 与 Node Key（文件权限 0600）
- `hz` 通过 Unix socket 与 `hzd` 通信，先实现 `hz status`（此时可以返回空内容）
- **完成标准**：`hzd` 重启后两把密钥不变
- 依赖：T01

### T05 Auth Key 注册（FR-1）
- `hz-coord` 的 bootstrap 子命令，可以在本机签发 Auth Key
- `hz up --auth-key`：完成注册，分配 Node Address 和 Node Name，绑定 Tag
- **完成标准**：满足 FR-1 的全部 AC
- 依赖：T04、T06

### T07 数据面：Linux 局域网直连（FR-7）
- 在 `hz-core` 中封装 boringtun 和 TUN，只路由 HzNet 的 IPv4 /16 和 IPv6 ULA 段
- 根据 Network Map 配置对端，使用对端的内网 Endpoint 直连
- WireGuard 收发数据和打洞共用同一个 UDP socket
- **完成标准**：**M1 达成**。两台 Linux Node 在同一局域网内能用 Node Address 互相 ping 通；在阿里云主机上验证 FR-4 的 AC
- 依赖：T05

## M2 跨 NAT

### T08 Network Map 流式下发（FR-6）
- 长连接双向流，推送全量和增量更新，Node 本地缓存
- 实现断线重连；Coordination Server 不可用时，Node 继续使用缓存
- 实现吊销和过期后把 Node 从 Network Map 中移除（这一步先不按 Policy 过滤，过滤在 T14 加入）
- **完成标准**：满足 FR-6 中"停掉 Coordination Server 10 分钟，会话不断"的 AC
- 依赖：T07

### T09 NAT 测试拓扑
- 用 netns 和 nftables 写脚本，搭出模拟公网、完全锥形 NAT、端口受限 NAT、对称型 NAT 几种环境
- 封装成 CI 中可以运行的集成测试框架（需要 privileged runner，或 self-hosted runner）
- **完成标准**：现有的 M1 场景能在拓扑中跑通（同一个 NAT 后面的两个 Node）
- 依赖：T07

### T10 Relay 与 Relayed Path（FR-9 的转发部分）
- `hz-relay`：TLS 443，按 Node Key 寻址转发，向 Coordination Server 校验 Node 身份
- `hzd`：连接 Relay，通过 Relay 收发 WireGuard 数据包
- **完成标准**：测试拓扑中两端都在对称型 NAT 后面时，能经 Relay 互相 ping 通；未注册的客户端被拒绝
- 依赖：T08、T09

### T11 NAT 穿透与路径升级（FR-8）
- 在 Relay 主机上提供 STUN（UDP 3478）
- 收集 Endpoint（内网、公网、IPv6）并上报
- 实现走 Relay 通道的打洞信令，用 Node Key 端到端加密
- 实现同时打洞：先走 Relayed Path，成功后升级为 Direct Path，直连失效时退回，IPv6 直连优先
- **完成标准**：**M2 达成**。测试拓扑中满足 FR-8 的各项 NAT 组合 AC
- 依赖：T10

### T12 网络变化恢复
- 监听网络接口和路由变化（以及休眠唤醒），触发 Endpoint 重新发现和路径重新协商
- **完成标准**：测试拓扑中模拟网络切换后，30 秒内恢复连通
- 依赖：T11

## M3 可控

### T13 交互式登录与有效期（FR-2、FR-3）
- Coordination Server 作为 OIDC 客户端对接 Kanidm，使用授权码流程加 PKCE；实现一次性登录链接
- 归属 User 的 Node 有效期默认 90 天；重新登录时轮换 Node Key
- 读取 groups claim，判定 `hznet_admins`
- **完成标准**：满足 FR-2 和 FR-3 的 AC（用本地 Kanidm 容器做集成测试）
- 依赖：T05

### T14 Policy（FR-10）
- 实现 TOML 格式解析与校验，Policy 带版本存储并支持回滚
- `hz policy push / get / rollback`
- Network Map 按 Policy 过滤，Policy 变更时增量重算
- 实现目标 Node 上的入站过滤（A1）
- **完成标准**：满足 FR-10 的 AC
- 依赖：T08、T13

### T15 Admin 与管理操作（FR-11）
- 通过 `hz` 进行远程管理，权限按所在 Node 的归属 User 判定（A3）
- Auth Key 的签发和吊销；Node 的列出、改名、删除、吊销
- 普通 User 只能操作自己名下的 Node
- **完成标准**：满足 FR-11 的 AC
- 依赖：T13

### T16 网内名字解析（FR-5）
- `hzd` 在 `100.96.0.53` 上提供本地 DNS 解析器（A2）
- Linux 用 systemd-resolved 配置分域 DNS，macOS 用 `/etc/resolver/`
- **完成标准**：满足 FR-5 的 AC
- 依赖：T08

## M4 可交付

### T17 macOS 支持
- 使用 utun，通过 launchd 运行守护进程，配置路由
- macOS 上的网络变化监听
- **完成标准**：macOS 冒烟测试通过（注册、直连、经 Relay 通信、名字解析）
- 依赖：T11（如果 T16 已完成，同时验证名字解析）

### T18 可观测性与 Relay 限速（FR-9 限速、FR-12）
- 实现每个 Node 的 Relay 限速（默认 10 Mbps）和按 Node 的流量统计
- `hz status` 显示每个对端走的路径（Direct Path 或 Relayed Path）和使用的 Endpoint；`hz ping` 显示走的路径
- 在 `/metrics` 中暴露：在线 Node 数、按 Node 的 Relay 流量、打洞成功率
- **完成标准**：满足 FR-9 的限速 AC；Prometheus 能抓取到上述指标
- 依赖：T11

### T19 分发（FR-13）
- 构建 musl 静态二进制（Linux x86_64 / aarch64）和 macOS arm64 二进制
- 编写 systemd 与 launchd 单元文件
- Coordination Server 提供 `install.sh`
- **完成标准**：在一台全新的 Linux 主机上，一条安装命令执行完再加上 `hz up`，这台主机就能加入 HzNet
- 依赖：T15、T17、T18

### T20 云主机部署与运维手册
- 申请证书，用 `coord.` / `relay.` / `auth.` 三个子域名
- 部署并初始化 Kanidm（OIDC 客户端、`hznet_admins` 组）
- 在安全组开放 TCP 443 和 UDP 3478
- 编写运维手册：bootstrap、备份 SQLite、升级流程
- **完成标准**：**M4 达成**。组织内的真实 Node（至少 1 台 macOS、1 台家宽后的 Linux、1 台云主机）组成 HzNet 并按 Policy 互访
- 依赖：T19
