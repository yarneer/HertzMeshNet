# v0.4 规格：macOS Client App

状态：已定稿（grilling 2026-10-28），待实现。术语以 [GLOSSARY.md](../GLOSSARY.md) 为准，架构取舍见 [ADR-0010](adr/0010-client-app-as-gui-shell.md)，权限分档见 [ADR-0011](adr/0011-ipc-member-tier-console-user.md)。

## 1. 动机

macOS 上的 Node 目前要靠 `sudo hzd install-launchd`、`sudo hz up` 和翻 `/Library/Logs/hzd.log` 来接入和排障，对组织里的普通 User 门槛太高。v0.4 给 macOS 提供一个菜单栏 Client App：拖进"应用程序"、授权一次、浏览器登录即可加入 HzNet，连接状态、对端路径和身份到期一眼可见，出问题时一键导出诊断包发给 Admin。

## 2. 范围

| 编号 | 需求 |
|---|---|
| MC-1 | hzd 新增 `down` 与持久化的 Desired State；`hz down` |
| MC-2 | IPC 权限分为只读档、成员档、管理档；成员档只对当前交互式会话用户开放 |
| MC-3 | IPC 新增 `subscribe`：推送完整 status 快照 |
| MC-4 | IPC 新增 `diagnostics`：脱敏的诊断信息，含最近日志 |
| MC-5 | 跨语言契约 fixture（Rust 生成、Swift 解码） |
| MC-6 | SwiftUI 菜单栏 App：状态、对端列表、通知 |
| MC-7 | 首次启动引导：浏览器登录 / 邀请码；`hznet://join` 深链 |
| MC-8 | App 内置 `hzd` 与 `hz`，经 SMAppService 注册；旧安装迁移；卸载 |
| MC-9 | Developer ID 签名与公证；Sparkle 2 更新，appcast 由 coord 提供 |

**定位**：Client App 只服务普通 User。Policy、Auth Key、邀请码签发、Node 管理留在 Admin Console 与 `hz` CLI。

**平台**：macOS 13 Ventura 及以上，仅 arm64。Windows 计划在 v0.5（见 §11）。

## 3. hzd 侧改动

### 3.1 `down` 与 Desired State（MC-1）

- **Desired State** 取 `up` / `down`，持久化在 state_dir 的 `desired_state.json`。缺省（旧安装升级上来）视为 `up`。
- `down`：停掉数据面（拆 utun、路由、`/etc/resolver/` 条目，停止向 coord 上报与拉取 Network Map），保留注册信息与密钥；写入 `down`。
- `up`（已注册）：按现有逻辑启动数据面，写入 `up`。未注册时的 `up` 语义不变（Auth Key / 邀请码 / 交互式登录）。
- hzd 启动时：已注册且 Desired State 为 `up` 才启动数据面。自动连接由此决定，App 不另存设置。
- `hz down` 同步上线，Linux 同样可用。
- v1 不做"退出登录"（注销身份）；需要时用 CLI 或在 Admin Console 删除 Node。

### 3.2 IPC 权限分档（MC-2）

| 档 | 方法 | 放行条件 |
|---|---|---|
| 只读档 | `status`、`ping`、`netcheck` | 任何本机用户 |
| 成员档 | `up`（仅交互式登录与邀请码）、`login_poll`、`down`、`subscribe`、`diagnostics` | 当前交互式会话用户，或 root / 与 hzd 同 uid |
| 管理档 | `up`（带 Auth Key）、`policy_*`、`authkey_*`、`invite_*`、`node_*` | root 或与 hzd 同 uid（不变） |

"当前交互式会话用户"是平台抽象：macOS 取 `/dev/console` 的属主 uid（与 SCDynamicStore 的 ConsoleUser 一致）；Windows 在 v0.5 取 WTS 活动会话用户。判定函数保持纯函数：输入 method、params 是否带 Auth Key、peer uid、daemon uid、console uid。

### 3.3 `subscribe`（MC-3）

- 请求 `{"id":n,"method":"subscribe","params":{}}` 后连接保持打开，同一 `id` 下逐行推送 `{"id":n,"result":<status>}`；`<status>` 与 `status` 方法返回的形状完全相同，并额外带 `desired_state`。
- 订阅建立时立即推一份；之后状态变化时推送，两次推送间隔至少 1 秒（合并抖动）；无变化时每 15 秒推一次作为心跳。
- 这是 IPC 第一个"一请求多响应"的方法；其他方法仍是一问一答。`REQUEST_TIMEOUT` 不适用于 `subscribe`。
- 客户端在 45 秒内没收到任何一行即视为断开。

### 3.4 `diagnostics`（MC-4）

返回 `{status, netcheck, version, os, arch, log_tail}`。`log_tail` 为 hzd 日志最近 2000 行，由 hzd 读取（普通用户未必能读 `/Library/Logs/hzd.log`）。脱敏：去掉私钥、Auth Key、邀请码、登录 URL 中的 token；保留 Node Name、Node Address 与 Endpoint（排障需要）。

## 4. 契约测试（MC-5）

- Rust 侧测试把典型响应写成 JSON fixture 到 `clients/fixtures/`：未注册、已注册（直连 / 部分 Relay / 冲突诊断）、已过期、已吊销、`down`、登录进行中、`diagnostics`。
- fixture 由测试生成并提交；CI 检查重新生成后无 diff，Swift 单元测试逐个解码。
- fixture 目录与平台无关，v0.5 的 Windows Client App 复用。

## 5. Client App（MC-6）

- SwiftUI `MenuBarExtra` + 设置窗口；后端访问封装在一个 `HzdBackend` 协议之后，v0.4 唯一实现是 UDS JSON-lines 客户端（为将来可能的 Network Extension 后端留缝，见 ADR-0010）。
- 连接 hzd 后先 `subscribe`，所有 UI 由最新快照驱动；断开时显示"hzd 未运行"，按 1s→2s→…→30s 指数退避重连。

**菜单栏图标状态**（自上而下取第一条命中）：

| 状态 | 条件 |
|---|---|
| hzd 未运行 | 连不上 socket |
| 需要重新登录 | `expired` 或 `revoked` |
| 与其他 VPN 冲突 | 诊断中检测到默认路由被虚拟网卡持有且 HzNet 路由失效（复用 #25） |
| 已断开 | Desired State 为 `down` |
| 部分中转 | 有 Relayed Path 对端，原因不是 `punch_pending` |
| 已连接 | 以上皆否 |

**菜单内容**：开关（up / down）；本机 Node Name 与 Node Address（点击复制）；对端列表（Node Name、Direct / Relayed 及原因、延迟，点击复制 `<name>.hznet.internal`）；"导出诊断包…"；"设置…"；"退出"（只退出 App，不改 Desired State）。

**系统通知**，只发这四种：距 `expires_at` 3 天；距 `expires_at` 1 天（带"重新登录"按钮）；检测到 VPN 冲突；coord 提示版本过旧。对端上下线不通知。

**导出诊断包**：调用 `diagnostics`，存为 `hznet-diagnostics-<node>-<时间>.zip`。

## 6. 首次启动与深链（MC-7）

- 未注册时打开引导窗口：Coordination Server 地址（预填 `DEFAULT_COORD_ADDR`，可改）+ 两种接入方式："浏览器登录"（`up` 拿到 `login_url` 后用 `NSWorkspace.open` 打开，再轮询 `login_poll`）与"输入邀请码"。GUI 不提供 Auth Key 输入。
- `hznet://join?coord=<https URL>&invite=<code>`：
  - 一律弹确认框，醒目显示 coord 域名；
  - 只接受 `https://` 的 coord；
  - 本机已注册到另一个 coord 时拒绝，提示改用 CLI；
  - 确认后按邀请码路径执行 `up`。

## 7. 安装、迁移与卸载（MC-8）

- App bundle 的 `Contents/MacOS/` 内置 `hzd` 与 `hz`，与 App 同版本；`Contents/Library/LaunchDaemons/com.hznet.hzd.plist` 由 `SMAppService.daemon(plistName:)` 注册，首次需要 User 在"系统设置 → 登录项"中批准。state_dir、socket 路径、日志路径与现状一致。
- macOS 上 Client App 是唯一安装方式；`install.sh` 检测到 macOS 时提示改用 App 并退出。
- **迁移**：发现旧的 `/Library/LaunchDaemons/com.hznet.hzd.plist` 时，引导 User 授权后卸载旧 plist、删除旧二进制，再注册新 daemon；state_dir 不变，注册信息保留。
- **命令行工具**：设置中"安装命令行工具"把 `hz` 软链到 `/usr/local/bin/hz`（需授权）。
- **卸载**：设置中"卸载"依次执行 `down`、注销 SMAppService daemon、清理 `/etc/resolver/` 条目与 `hz` 软链；询问是否同时删除本机身份（Machine Key / Node Key），默认保留，重装后仍是同一个 Node。

## 8. 签名、更新与工程（MC-9）

- 代码在 `clients/macos/`，Xcode 工程由 XcodeGen 从 `project.yml` 生成，不提交 `.pbxproj`。构建脚本先 `cargo build --release -p hzd -p hz`，再拷入 bundle 并签名。
- CI 新增 macOS job：构建、Rust 与 Swift 测试、fixture 无 diff 检查、打包；仅 tag 时 Developer ID 签名 + 公证（证书在 GitHub Secrets）。
- **更新**：Sparkle 2，每天检查一次，发现新版提示 User 确认后再装，不静默升级（不违背"Node 不自动升级"）。appcast 与 `.dmg` 由 `hz-coord` 在现有分发 `install.sh` 的路径下提供，EdDSA 签名。更新后 App 重新注册 daemon，使新 `hzd` 生效。
- 版本号与 workspace `version` 一致。

## 9. 不做

- 管理功能（Policy、Auth Key、邀请码签发、Node 管理）。
- 退出登录 / 切换账号。
- Network Extension、Mac App Store 上架、Intel Mac、macOS 12 及以下。
- 静默自动更新。
- 对端上下线通知。

## 10. 测试

| 层 | 覆盖 |
|---|---|
| 单元（Rust） | 权限分档判定（§3.2 每条一行表驱动，含 `up` 带 / 不带 Auth Key）；Desired State 读写与缺省；`subscribe` 合并节流与心跳；`diagnostics` 脱敏 |
| 契约 | fixture 生成无 diff；Swift 解码全部 fixture |
| 单元（Swift） | 菜单栏状态判定（§5 表驱动）；深链校验（非 https、已注册到别的 coord）；到期通知时点 |
| Seam B | `down` 后 Network Map 流断开、重启 hzd 后保持 `down`；`subscribe` 在注册 / 登录完成 / `down` 时各推一份 |
| macOS 手工冒烟 | 全新安装 → 登录项批准 → 浏览器登录 → 互通；从 launchd 旧安装迁移且身份不变；深链加入；Sparkle 升级；卸载保留身份后重装 |

## 11. 跨平台预留（Windows v0.5）

- IPC 方法与权限分档只描述语义，"当前交互式会话用户"由平台各自实现。
- 契约 fixture 在 `clients/fixtures/`，与平台无关。
- Windows Client App 另做原生壳（WinUI 或 Tauri，届时决定），与 macOS 共享的是 IPC 契约而非 UI 代码。Windows 的主要工作量在 hzd 数据面：Wintun、Windows Service、`IP_UNICAST_IF` 与路由监听、NRPT 分域 DNS。

## 12. 交付顺序

1. hzd：`down` 与 Desired State、权限分档、`subscribe`、`diagnostics`、`hz down`（可独立合入）
2. 契约 fixture 与 Swift IPC 客户端
3. 菜单栏 App 与首次启动引导、深链
4. SMAppService 安装、迁移、卸载、`hz` 软链
5. 签名、公证、Sparkle 与 coord 提供 appcast
6. 文档：安装手册 macOS 章节改写、`macos-smoke-test.md` 更新

## 13. 验收

- [ ] 一台从未装过 HzNet 的 macOS 13+ arm64 机器，从下载 `.dmg` 到与 Linux Node 互通，全程无需终端
- [ ] 从 v0.3 launchd 安装迁移后 Node Name、Node Address 不变
- [ ] `down` 后重启机器仍为断开；`up` 后重启自动连接
- [ ] 普通 User 能在 App 里 up / down / 登录，不能通过 IPC 签发 Auth Key 或改 Policy
- [ ] 身份到期前 3 天、1 天收到通知，点"重新登录"可续期
- [ ] 诊断包不含私钥、Auth Key、邀请码与登录 token
- [ ] Sparkle 能从 coord 拉到新版本并在 User 确认后升级
