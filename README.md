# HertzMeshNet

**私有部署的点对点组网系统**：让一个组织内分散在各种 NAT 后面的 Linux / macOS 机器，组成一张彼此可直接寻址的加密虚拟网络（HzNet）。能直连时直连，不能直连时经 Relay 中转，访问范围受 Policy 约束。

**A self-hosted peer-to-peer mesh network**: connect your organization's Linux / macOS machines scattered behind various NATs into one encrypted, directly addressable virtual network (an HzNet). Direct when possible, relayed when not, with access governed by Policy.

[![CI](https://github.com/yarneer/HertzMeshNet/actions/workflows/ci.yml/badge.svg)](https://github.com/yarneer/HertzMeshNet/actions/workflows/ci.yml)
[![Seam A](https://github.com/yarneer/HertzMeshNet/actions/workflows/seam-a.yml/badge.svg)](https://github.com/yarneer/HertzMeshNet/actions/workflows/seam-a.yml)

> 本 README 中英对照，每节先中文后英文。
> This README is bilingual: Chinese first, English follows in each section.
> 术语以 [GLOSSARY.md](GLOSSARY.md) 为准 · Terminology is defined in [GLOSSARY.md](GLOSSARY.md).

## 它解决什么问题 · The problem it solves

机器分散在家庭宽带、办公网、各家云厂商的内网里，彼此被 NAT 隔开。传统方案要么开公网端口（危险），要么逐台维护 VPN（繁琐）。HertzMeshNet 在自己的云主机上部署一套控制面，所有 Node 之间用 WireGuard 加密直接通信，按名字或固定地址互访，不需要任何一台机器暴露公网端口。

Machines sit behind NATs in homes, offices and cloud VPCs. The alternatives are exposing public ports (dangerous) or maintaining pairwise VPNs (tedious). HertzMeshNet runs a control plane on your own cloud host; nodes talk to each other with WireGuard encryption, directly, addressed by stable name or address — no machine needs a public listening port.

定位说明：

- 全栈自研协议，**不兼容**官方 Tailscale 客户端或协议（[ADR-0001](docs/adr/0001-full-stack-own-protocol.md)）。
- 按单组织自部署设计：单实例 Coordination Server + SQLite，目标规模 500 个 Node，不做多租户。
- 针对中国大陆云主机部署优化：三个服务共用已备案域名的 TCP 443，按 TLS SNI 分流；服务端为 musl 静态二进制 + systemd，不用容器（[ADR-0004](docs/adr/0004-mainland-china-deployment.md)）。
- 项目以学习驱动，但以"本组织真实可用"为验收标准。

Positioning:

- A fully self-developed protocol — **not** compatible with official Tailscale clients or protocol ([ADR-0001](docs/adr/0001-full-stack-own-protocol.md)).
- Designed for single-organization self-hosting: one Coordination Server + SQLite, targeting up to 500 nodes, no multi-tenancy.
- Tuned for mainland-China cloud deployment: all three services share TCP 443 on one ICP-registered domain, split by TLS SNI; servers ship as musl static binaries under systemd, no containers ([ADR-0004](docs/adr/0004-mainland-china-deployment.md)).
- Learning-driven, but with "real production use by this organization" as the acceptance bar.

## 架构 · Architecture

```
                    ┌──────────────── 公网 Internet ────────────────┐
                    │  coord.example.com   gRPC over TLS 443        │  注册 · Network Map 推送
                    │                                            │   · OIDC 回调 · 分发
                    │  relay.example.com   TLS 443 + STUN UDP 3478 │  加密流量中转 · 公网发现
                    │  auth.example.com    Kanidm (OIDC IdP)       │  用户身份
                    └────────────────────────────────────────────┘
                          ▲ 控制面                    ▲ 数据面
                          │                          │ WireGuard UDP（打洞直连）
                          │                          │ 或 TLS（经 Relay 中转）
        ┌──── Node A ─────┴───────┐      ┌───────────┴───── Node B ──┐
        │ hzd   root 守护进程      │ ◄──► │ hzd                        │
        │       TUN/utun + 用户态  │      │       TUN/utun + 用户态    │
        │       WireGuard         │      │       WireGuard           │
        │ hz    命令行工具        │      │ hz    命令行工具           │
        └─────────────────────────┘      └───────────────────────────┘
          100.96.0.0/16 + ULA IPv6 —— Direct Path 优先（IPv6 优先），失败退回 Relayed Path
```

| 组件 | 形态 | 职责 |
|---|---|---|
| `hz-coord` | 服务端二进制 | 控制面：Node 注册与认证、地址与名字分配、Network Map 推送、Policy 存储与校验、OIDC 回调、`install.sh` 分发。SQLite 存储，gRPC + HTTP |
| `hz-relay` | 服务端二进制 | 数据面兜底：转发 Node Key 加密后的流量（看不到明文），内置 STUN，按 Node 限速与统计 |
| `hzd` | Node 守护进程（root） | 用户态 WireGuard（`boringtun`）、TUN/utun 收发、NAT 打洞、`*.hznet.internal` DNS 应答、入站 Policy 过滤 |
| `hz` | Node 命令行工具 | `status` / `up` / `login` / `policy` / `authkey` / `node` / `ping`，经本地 Unix socket 与 `hzd` 通信 |
| `hz-proto` | 库 | `hz.v1` protobuf 协议定义与代码生成（`protox` 编译，无需系统 `protoc`） |
| `hz-core` | 库 | 共享逻辑：coord 客户端、`hzd`↔`hz` IPC、WireGuard 数据面引擎等 |

English summary: `hz-coord` is the control-plane server (registration, auth, address/name allocation, Network Map streaming, Policy storage, OIDC callback, install-script distribution; SQLite, gRPC + HTTP). `hz-relay` is the fallback data plane (forwards Node-Key-encrypted traffic, blind to plaintext; built-in STUN, per-node rate limiting). `hzd` is the root daemon on each node (userspace WireGuard via `boringtun`, TUN/utun, NAT hole punching, `*.hznet.internal` DNS, inbound Policy filtering). `hz` is the unprivileged CLI talking to `hzd` over a Unix socket. `hz-proto` holds the `hz.v1` protobuf definitions; `hz-core` holds shared logic.

## 关键设计 · Key design decisions

- **用户态 WireGuard**：数据面用 `boringtun` 在用户态实现，不依赖内核模块；打洞与 WireGuard 收发共用同一个 UDP socket（[ADR-0002](docs/adr/0002-userspace-wireguard.md)）。
- **地址段**：默认 `100.96.0.0/16`（避开阿里云 `100.100.0.0/16`），每个 Node 另有一个 ULA IPv6 地址；`hzd` 只把该段路由进 TUN（[ADR-0003](docs/adr/0003-node-address-range.md)）。
- **两把密钥**：Machine Key（Ed25519，长期设备身份，挑战签名认证，不用 mTLS）与 Node Key（WireGuard 数据面密钥，重新登录时轮换）（[ADR-0005](docs/adr/0005-machine-key-and-node-key.md)）。
- **按 Policy 裁剪的 Network Map**：下发给某 Node 的 Map 只含 Policy 允许互访的对端及其公钥与 Endpoint；控制面宕机后已连接 Node 照常通信（[ADR-0006](docs/adr/0006-network-map-filtered-by-policy.md)）。
- **Policy 在目标端执行**：TOML 声明式规则，整份替换、校验失败拒绝、保留历史可回滚；除 Network Map 裁剪外，目标 Node 的 `hzd` 还按 Policy 过滤入站流量，实现端口级控制。
- **与其他 TUN 类工具共存**：`hzd` 的隧道外层流量（打洞 UDP、STUN、到 Coordination Server / Relay 的连接）绑定物理出口网卡（macOS `IP_BOUND_IF`、Linux `SO_BINDTODEVICE`），不进入第三方虚拟网卡；物理出口变化自动重绑。
- **协议版本策略 N-2**：Coordination Server 至少兼容最近两个版本，更旧的 Node 被明确拒绝并提示升级。
- **网内名字解析**：`<Node Name>.hznet.internal` 由 `hzd` 在保留地址 `100.96.0.53` 本地应答；Linux 走 systemd-resolved 分域、macOS 走 `/etc/resolver/`，不接管系统其他 DNS。

English: **Userspace WireGuard** via `boringtun`, sharing one UDP socket for both hole punching and data ([ADR-0002](docs/adr/0002-userspace-wireguard.md)). **Address range** defaults to `100.96.0.0/16` (avoiding Alibaba Cloud's `100.100.0.0/16`) plus a ULA IPv6 per node ([ADR-0003](docs/adr/0003-node-address-range.md)). **Two keys per node**: a long-lived Ed25519 Machine Key (challenge-response auth, no mTLS) and a WireGuard Node Key rotated on re-login ([ADR-0005](docs/adr/0005-machine-key-and-node-key.md)). **Policy-filtered Network Map**: each node only receives peers Policy allows, and keeps working when the control plane is down ([ADR-0006](docs/adr/0006-network-map-filtered-by-policy.md)). **Policy enforced at the destination node** for port-level control, with validated whole-file replace and versioned rollback. **Coexists with other TUN tools**: outer traffic binds to the physical interface (`IP_BOUND_IF` / `SO_BINDTODEVICE`) and rebinds when the default route changes. **N-2 protocol compatibility**. **Magic DNS**: `<node-name>.hznet.internal` answered locally by `hzd` on `100.96.0.53`, via systemd-resolved split-DNS on Linux and `/etc/resolver/` on macOS.

## 构建与测试 · Build & test

要求 Rust 1.85+（edition 2024）。Requires Rust 1.85+ (edition 2024).

```sh
cargo build --release          # 构建 / build
cargo fmt --all                # 格式化 / format
cargo clippy --all-targets -- -D warnings   # lint
cargo test --all               # 单元与集成测试 / unit & integration tests
```

**Seam A —— NAT 拓扑集成门禁**：在单个特权 Docker 容器内用 network namespace + nftables 搭建模拟公网与三种 NAT（全锥 / 端口受限 / 对称型），端到端验证注册、直连打洞、Relay 兜底、Policy、限速、Admin 吊销、网络切换恢复、与接管默认路由的第三方 TUN 工具共存等场景（清单见 `scripts/test/topo/scenarios/`）。CI 在每次 push 时全量运行；本机一键复跑：

**Seam A — the NAT-topology integration gate**: inside one privileged Docker container, network namespaces + nftables simulate a public internet and three NAT types (full-cone / port-restricted / symmetric), end-to-end verifying registration, direct-path hole punching, relay fallback, Policy, rate limiting, admin revocation, network-change recovery, and coexistence with a default-route-hijacking third-party TUN tool across 15 scenarios. CI runs all of them on every push; locally:

```sh
bash scripts/test/topo/docker_run.sh build        # 容器内构建二进制
bash scripts/test/topo/docker_run.sh run lan      # 跑单个场景，如 lan
bash scripts/test/topo/docker_run.sh selftest     # NAT 行为自检
```

场景清单见 `scripts/test/topo/scenarios/`。macOS 只做手工冒烟测试，清单见 [docs/macos-smoke-test.md](docs/macos-smoke-test.md)。

See `scripts/test/topo/scenarios/` for the full scenario list. macOS is covered by a manual smoke checklist: [docs/macos-smoke-test.md](docs/macos-smoke-test.md).

## 快速上手 · Quick start

生产部署（nginx SNI 分流、ACME 证书、Kanidm、systemd）按 [docs/runbook.md](docs/runbook.md) 逐步照抄即可。开发/体验核心链路的最小形态：

For production deployment (nginx SNI splitting, ACME certificates, Kanidm, systemd), follow [docs/runbook.md](docs/runbook.md) step by step. The minimal path to try the core flow in development:

```sh
# 1. 启动 Coordination Server（自签 TLS 即可起步）
#    Start the Coordination Server (self-signed TLS is fine to start)
hz-coord serve --db hz.db --listen 127.0.0.1:443 \
  --tls-cert cert.pem --tls-key key.pem \
  --http-listen 127.0.0.1:8443 --oidc-issuer https://auth.example.com --oidc-client-id hznet

# 2. 本机签发第一把 Auth Key（明文只显示这一次；--make-admin 种出第一个 Admin）
#    Issue the first Auth Key locally (plaintext shown once; --make-admin seeds the first Admin)
hz-coord bootstrap --db hz.db --expire 30d --tag db --make-admin alice

# 3. Node 注册并加入 HzNet
#    Register the node and join the HzNet
sudo hzd &                                    # HZD_COORD_ADDR 指向 coord 地址
sudo hz up --auth-key <key>

# 4. 验证与管理
#    Verify and manage
hz status                                     # 本机状态与 Network Map
hz ping db-1                                  # 对端时延与当前路径
ping db-1.hznet.internal                      # 网内名字解析
hz policy push policy.toml                    # 整份替换 Policy（TOML）
hz authkey create --expiry 7d --once --tag db  # 签发一次性 Auth Key（需 Admin，至少一个 Tag）
```

支持平台：Linux x86_64 / aarch64（systemd），macOS arm64（launchd）。安装脚本 `https://coord.<域名>/install.sh` 按平台下发二进制并注册系统服务。

Supported platforms: Linux x86_64 / aarch64 (systemd) and macOS arm64 (launchd). The installer at `https://coord.<domain>/install.sh` downloads platform binaries and registers the system service.

## 项目状态 · Status

MVP 各功能票（注册、数据面、NAT 穿透、Map 推送、交互式登录、Policy、Admin、有效期、Relay 限速、macOS、分发、部署手册、DNS 场景进 CI、地址段可配置）已全部实现并通过自动化门禁。真实云主机上的三机部署验收为人工步骤，服务器手册见 [docs/runbook.md](docs/runbook.md)，Node 安装手册见 [docs/install-guide.md](docs/install-guide.md)。

All MVP feature tickets (registration, data plane, NAT traversal, Map streaming, interactive login, Policy, admin, expiry, relay rate limiting, macOS, distribution, deployment runbook, DNS scenario in CI, configurable address range) are implemented and pass the automated gates. Real three-node deployment on a cloud host is a manual acceptance step — see [docs/runbook.md](docs/runbook.md) for the server side and [docs/install-guide.md](docs/install-guide.md) for installing nodes.

## 更多文档 · Further reading

| 文档 | 内容 |
|---|---|
| [docs/install-guide.md](docs/install-guide.md) | Node 安装手册：一条命令安装、注册、验证、升级、卸载 / Install guide: one-command install, registration, verification, upgrade, uninstall |
| [docs/mvp-spec.md](docs/mvp-spec.md) | MVP 规格说明：13 条功能需求与验收标准 / MVP spec: 13 functional requirements with acceptance criteria |
| [docs/adr/](docs/adr/) | 架构决策记录 / Architecture decision records |
| [docs/admin-console-v1.md](docs/admin-console-v1.md) | Admin Console v1 范围：页面、HTTP API、部署摩擦 / Admin Console v1 scope |
| [docs/runbook.md](docs/runbook.md) | 云主机部署与运维手册 / Cloud deployment & operations runbook |
| [docs/mvp-tasks.md](docs/mvp-tasks.md) | 任务分解与进度 / Task breakdown & progress |
| [GLOSSARY.md](GLOSSARY.md) | 术语表（中英）/ Terminology (bilingual) |

## 许可证 · License

Copyright 2026 Xin Li (yarneer)

本仓库以 [Apache License 2.0](LICENSE) 授权。
Licensed under the [Apache License, Version 2.0](LICENSE).
