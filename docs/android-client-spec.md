# v0.4 补充规格：Android Client App

状态：已定稿（grilling 2026-11-03），待实现。术语以 [GLOSSARY.md](../GLOSSARY.md) 为准；架构取舍见 [ADR-0012](adr/0012-android-vpnservice-in-process-engine.md)（VpnService 进程内引擎）与 [ADR-0013](adr/0013-hz-engine-platform-trait.md)（抽出 `hz-engine`）。本文是 [macos-client-spec](macos-client-spec.md) 的同版本补充，凡未另行说明的行为（Desired State、`subscribe` 快照形状、`diagnostics` 脱敏、深链校验、"不做"清单）与之一致。

## 1. 动机与优先级

组织里有 User 需要从手机访问 HzNet 上的机器（SSH、内网 Web、远程桌面）。Android 上没有 root，现有"root 守护进程 + CLI"的形态无法安装，User 目前完全不能接入。

**v0.4 内 Android 优先于 macOS 收尾**：macOS 剩余票（#91–#94：SMAppService 安装、迁移与卸载、签名公证与 Sparkle、文档）暂停；Android 完成后以 `0.4.0` 首发（内含已合入的 hzd 侧 `down`、权限分档、`subscribe`、`diagnostics`），macOS Client App 收尾后在 `0.4.x` 发布。macOS 正式发布前，Mac 上的 Node 继续用现有 launchd 方式安装。

不上 Google Play：APK 由 Coordination Server 分发，App 内提示更新。

## 2. 范围

| 编号 | 需求 |
|---|---|
| MA-1 | 抽出 `hz-engine`：`hzd` 的编排逻辑与平台能力解耦，配置改为 `EngineConfig` |
| MA-2 | Coordination Server 下发 Relay 与 STUN 地址；Node 端按优先级取用 |
| MA-3 | 引擎 DNS 应答器的转发模式 |
| MA-4 | 引擎 keepalive 参数化（移动端档位） |
| MA-5 | `hz-android` JNI 桥与 Android `Platform` 实现 |
| MA-6 | VpnService 生命周期：前台服务、Desired State、开机恢复、被抢占 |
| MA-7 | Compose UI：状态、开关、对端列表、引导（浏览器登录 / 邀请码）、`hznet://join` 深链 |
| MA-8 | 通知与诊断包 |
| MA-9 | APK 构建、签名、coord 分发与 App 内更新 |
| MA-10 | CI、契约测试与 Android 冒烟清单 |

**定位**：与 macOS 一致，Client App 只服务普通 User。Policy、Auth Key、邀请码签发、Node 管理留在 Admin Console 与 `hz` CLI。

**Node 角色**：Android 设备是完整的 Node：有 Node Name 与 Magic DNS 名字，其他 Node 可按 Policy 访问它，入站 Policy 过滤照常生效。手机多处于运营商对称 NAT 之后，预期大量走 Relayed Path。

**平台**：Android 9（API 28）及以上；release 仅 arm64-v8a，debug 另加 x86_64 供模拟器使用。

## 3. 引擎重构（MA-1，ADR-0013）

### 3.1 边界

新建 crate `hz-engine`，承接现 `hzd/src/lib.rs` 中 `Daemon` 的编排逻辑：会话与注册、交互式登录轮询、Network Map 流、数据面监督（启动 / `down` / 重启）、Endpoint 采集与上报、Relay 监督、STUN 与 netcheck、Health Report、`diagnostics`、Desired State 读写，以及请求分发（`handle_request`）。`hz_core::wire::Engine`（sans-IO 的 WireGuard 状态机）保持不变。

`hzd` 只保留桌面专属部分：UDS IPC 服务器与 uid 分档判定、launchd / systemd 集成、路由守护与 VPN 冲突检测、系统 DNS 接入（systemd-resolved 分域、`/etc/resolver/`、resolv.conf 回退）、Port Map。

### 3.2 `Platform` trait

```rust
trait Platform: Send + Sync {
    /// 一次性提交地址、路由、DNS、MTU，返回 TUN fd。
    fn establish(&self, spec: TunSpec) -> anyhow::Result<TunFd>;
    /// 让外层 socket 不进入本 HzNet 的 TUN。
    fn protect(&self, fd: RawFd) -> bool;
    /// 物理网络变化事件流。
    fn net_events(&self) -> Receiver<NetEvent>;
    /// 物理网络当前的 DNS 服务器。
    fn system_dns(&self) -> Vec<IpAddr>;
}
```

- `establish` 采用原子语义，与 Android `VpnService.Builder.establish()` 对齐；桌面实现在内部依次执行"创建 tun/utun → 配地址与路由 → 接入系统 DNS"，即现有逻辑。重复调用（网络切换、`up` 恢复）以新 fd 替换旧 fd。
- `protect`：桌面实现为现有的绑定物理出口网卡（`SO_BINDTODEVICE` / `IP_BOUND_IF`）；Android 实现回调 `VpnService.protect(fd)`。引擎创建的每个外层 socket（WireGuard UDP、STUN、到 coord 与 Relay 的 TCP、DNS 转发）都必须经过它。
- `net_events`：Linux 为 netlink，macOS 为现有轮询，Android 由 Kotlin 侧 `ConnectivityManager.NetworkCallback` 推送。
- 路由守护、冲突检测、Port Map 不进 trait。

### 3.3 配置

`EngineConfig` 结构体承载现有全部 `HZD_*` 环境变量的语义（coord 地址、Relay / STUN 地址、WireGuard 端口、bootstrap DNS、DNS 后缀、强制 Relay、Relay CA、keepalive 档位、DNS 模式等）。环境变量只在 `hzd` 的 `main` 中解析成 `EngineConfig`；Android 由 Kotlin 以 JSON 传入。

### 3.4 交付约束

本节作为 Android 工作的第一个 PR 独立合入：Linux / macOS 的 Seam A、Seam B 全绿，`hzd` 与 `hz` 对外行为（IPC 方法与响应、CLI 输出、文件路径）不变。

## 4. Relay / STUN 地址下发（MA-2）

- `coord.proto` 的注册响应与 Network Map 新增 optional 字段 `relay_addr`、`stun_addrs`（repeated）。`hz-coord` 新增启动参数 `--public-relay-addr`、`--public-stun-addr` 配置其值，缺省不下发。
- Node 端取值优先级：`EngineConfig` 显式值（桌面即环境变量）> coord 下发 > 按 ADR-0004 由 coord 主机名推导（`coord.<域名>` → `https://relay.<域名>`，STUN 取 `relay.<域名>:3478`）。
- 旧 coord 不带字段时走推导，符合 N-2 兼容。桌面端同样受益，`install.sh` 之后可不再写这两个变量（本票不强制改脚本）。
- 本节作为独立票先于 JNI 工作合入，同时解决 macOS #91 的同一缺口。

## 5. 网络行为

### 5.1 路由（Android）

`TunSpec` 只包含 `network_cidr`（默认 `100.96.0.0/16`）与本 HzNet 的 ULA 前缀；其余流量走物理网络。Kotlin 侧调用 `setUnderlyingNetworks` 跟随当前物理网络，使系统正确判断是否按流量计费。不做按 App 分流，不做全隧道。

### 5.2 Magic DNS 转发模式（MA-3）

Android 上 VpnService 一旦声明 DNS 服务器，走 VPN 网络的 App 的全部 DNS 查询都会发往该地址，而现有应答器对后缀外查询回 REFUSED、不递归。引擎 DNS 应答器新增"转发模式"，由 `EngineConfig` 开启（仅 Android 使用）：

- `*.<dns_suffix>` 由引擎按 Network Map 本地应答，行为与现有一致。
- 后缀外查询经 `protect()` 过的 socket 原样转发给 `Platform::system_dns()` 返回的服务器，UDP 优先、截断时改 TCP；依次尝试，全部失败回 SERVFAIL。网络切换后使用新的服务器列表。
- TUN 声明的 DNS 服务器为 `dns_v4`（默认 `100.96.0.53`）。
- 系统开启"私人 DNS"严格模式时，Magic DNS 可能失效：App 检测到后提示一次，不阻止连接。

桌面端不开启转发模式，仍然分域接管。

### 5.3 keepalive（MA-4）

WireGuard persistent keepalive 与 coord 长连接 HTTP/2 keepalive 改为 `EngineConfig` 参数：桌面保持 8 秒 / 20 秒；Android 档位为 25 秒 / 60 秒。25 秒基于运营商 UDP NAT 映射超时通常大于 30 秒的经验；冒烟中若发现空闲直连频繁退回 Relay，再调整。

## 6. JNI 桥（MA-5）

crate `hz-android`（依赖 `hz-engine`，产物 `libhz_android.so`，经 `cargo-ndk` 构建）暴露：

| 方向 | 接口 | 说明 |
|---|---|---|
| Kotlin → Rust | `start(configJson, platform)` | 在独立 tokio 运行时上启动引擎；state_dir 为 App 的 `filesDir/hznet` |
| Kotlin → Rust | `request(json) -> json` | 复用 `handle_request`，固定按成员档执行；管理档方法（带 Auth Key 的 `up`、`policy_*`、`authkey_*`、`invite_*`、`node_*`）一律拒绝 |
| Kotlin → Rust | `subscribe(callback)` | 推送与 IPC `subscribe` 同形状的快照（含 `desired_state`），节流与心跳规则相同 |
| Kotlin → Rust | `stop()` | 停止数据面与运行时 |
| Kotlin → Rust | `onNetworkChanged(dnsServersJson)` | Kotlin 推送物理网络变化与当前 DNS 服务器，驱动 `net_events` 与 `system_dns` |
| Rust → Kotlin | `establish(tunSpecJson) -> fd` | Kotlin 用 `VpnService.Builder` 建立 TUN，返回 detach 后的 fd |
| Rust → Kotlin | `protect(fd) -> bool` | 调用 `VpnService.protect` |

- 跨语言契约为 JSON 字符串，Kotlin 侧以 `clients/fixtures/` 做解码测试。
- 日志经 tracing layer 同时写入 logcat 与内存环形缓冲区（最近 2000 行），`diagnostics` 的 `log_tail` 取自该缓冲区。
- **密钥**：沿用"state_dir 下私钥文件是唯一事实源"，不使用 Android Keystore。Manifest 设 `allowBackup=false`，`dataExtractionRules` 排除 state_dir，防止身份经云备份或设备迁移复制到另一台设备。
- **Node Name**：引导页预填 `Build.MODEL` 规范化结果（小写、非字母数字转 `-`、去首尾 `-`，如 `pixel-8`），User 可改，作为注册参数传给 coord；重名沿用 coord 现有消歧规则。

## 7. VpnService 生命周期（MA-6，ADR-0012）

- 引擎运行在 `VpnService` 所在进程。连接期间为前台服务，带常驻通知（显示状态，点击打开 App）。
- 首次 `up` 前调用 `VpnService.prepare` 获取用户同意。
- 沿用 Desired State：`up` / `down` 由引擎持久化在 state_dir。开机时 `BOOT_COMPLETED` 接收器检查到已注册且 Desired State 为 `up`、且已获 VPN 同意时启动服务。兼容系统"始终开启的 VPN"：由系统拉起时按已注册状态启动数据面，Desired State 为 `down` 时也遵从系统意图启动并写回 `up`。
- **被抢占**：其他 VPN 启动导致 `onRevoke` 时，停止数据面、把 Desired State 写为 `down`、进入"被其他 VPN 接管"状态并发通知。Android 同一时间只允许一个 VpnService，HzNet 与其他 VPN / 代理类 App 互斥（ADR-0012）。
- 不主动申请电池优化白名单；诊断页提示"后台常断开时可将本 App 加入白名单"并提供跳转。

## 8. Client App（MA-7、MA-8）

技术栈：Kotlin + Jetpack Compose，单 Activity。代码在 `clients/android/`，Gradle Kotlin DSL。后端访问封装在 `HzBackend` 接口之后，唯一实现是 JNI 桥；视图模型只依赖该接口，是 Kotlin 侧的测试 seam。

**状态**（自上而下取第一条命中）：

| 状态 | 条件 |
|---|---|
| 未授权 VPN | 尚未取得 `VpnService.prepare` 同意 |
| 未注册 | 快照 `registered=false` → 进入引导 |
| 需要重新登录 | `expired` 或 `revoked` |
| 被其他 VPN 接管 | 最近一次断开原因为 `onRevoke` 且 Desired State 为 `down` |
| 已断开 | Desired State 为 `down` |
| 部分中转 | 有 Relayed Path 对端，原因不是 `punch_pending` |
| 已连接 | 以上皆否 |

**主界面**：连接开关；本机 Node Name 与 Node Address（点击复制）；对端列表（Node Name、Direct / Relayed 及原因、延迟，点击复制 `<name>.hznet.internal`）；"导出诊断包"；"设置"（coord 地址只读展示、版本、检查更新、电池白名单提示）。

**引导**：coord 地址（预填默认值，可改）+ Node Name（预填，见 §6）+ 两种接入方式：

- "浏览器登录"：`up` 得到 `login_url` 后用 Custom Tabs 打开，App 轮询 `login_poll`；完成后把自己切回前台。不做 App Link 或自定义 scheme 回跳，coord 不改。
- "输入邀请码"。
- 不提供 Auth Key 输入。

**深链** `hznet://join?coord=<https URL>&invite=<code>`：校验规则与 macOS 相同（一律确认框并醒目显示 coord 域名；只接受 `https://`；已注册到不同 coord 时拒绝并提示改用 CLI；确认后按邀请码路径 `up`）。

**通知**（只发这些）：

- 距 `expires_at` 3 天；1 天（带"重新登录"）。由 WorkManager 按 `expires_at` 调度，VPN 关闭时也能触发；`expires_at` 变化时重排。
- 被其他 VPN 接管。
- 有新版本（§9，同时覆盖 coord 提示版本过旧的情形）。
- 对端上下线不通知。

**诊断包**：调用 `diagnostics`（脱敏规则同 macOS），加上 App 版本、Android 版本、机型、私人 DNS 模式、是否在电池白名单，打包为 `hznet-diagnostics-<node>-<时间>.zip`，经系统分享面板发出。

## 9. 构建、签名、分发与更新（MA-9）

- 构建：Gradle 任务先 `cargo ndk -t arm64-v8a [-t x86_64] build -p hz-android --release`，再把 `.so` 打进 APK。versionName 与 workspace `version` 一致，versionCode 由版本号推导单调递增。
- 签名：release keystore 存 GitHub Secrets，另行离线备份；丢失即无法覆盖升级，需在 runbook 中写明保管方式。
- 分发：发布时把 APK 放到 coord 分发目录 `android-arm64/hznet.apk`；`/dl/manifest.json` 的扫描规则放宽，自动列出其 sha256。下载地址 `/dl/android-arm64/hznet.apk`。安装手册新增"Android：浏览器打开 `https://coord.<域名>/dl/android-arm64/hznet.apk` 安装"。
- 更新：App 每天拉一次 `/dl/manifest.json`，`version` 高于自身 versionName 时通知 User；User 确认后下载到 cache、校验 sha256，交给系统安装器（`REQUEST_INSTALL_PACKAGES`）。签名一致性由系统保证。不静默升级，不依赖 Google Play 服务或 FCM。

## 10. 不做

- 管理功能（Policy、Auth Key、邀请码签发、Node 管理）。
- 退出登录 / 切换账号。
- Google Play 上架、Play 服务依赖、FCM 推送。
- 全隧道、出口节点、按 App 分流。
- 与其他 VPN 同时开启。
- Android Keystore 存放身份密钥。
- 32 位 ARM、Android 8 及以下。
- 静默自动更新；对端上下线通知。
- CI 中的模拟器仪器测试（由手工冒烟覆盖）。

## 11. 测试

| 层 | 覆盖 |
|---|---|
| Seam A / B（现有） | `hz-engine` 抽出后 Linux / macOS 全绿，行为不变 |
| 单元（Rust） | `Platform` 假实现驱动引擎：`establish` 收到的 `TunSpec` 只含 HzNet 网段与 DNS；所有外层 socket 都经过 `protect`；`net_events` 触发重绑与 Endpoint 重采；DNS 转发模式（后缀内本地应答、后缀外转发、截断改 TCP、全失败 SERVFAIL、服务器列表更新）；Relay / STUN 地址三级优先级；keepalive 档位生效；JNI `request` 拒绝管理档方法 |
| Seam B 扩展 | 进程内 coord 配置 `--public-relay-addr` 时注册响应与 Network Map 携带地址，未配置时不携带 |
| 契约 | Kotlin 解码 `clients/fixtures/` 全部 fixture |
| 单元（Kotlin） | 状态判定（§8 表驱动）；深链校验；到期通知时点与重排；版本比较与 sha256 校验；Node Name 规范化 |
| Android 手工冒烟 | `docs/android-smoke-test.md`，覆盖 §13 全部条目 |

## 12. 交付顺序

1. `hz-engine` 抽出与 `Platform` trait（MA-1），独立合入
2. coord 下发 Relay / STUN 地址（MA-2），可与 1 并行
3. DNS 转发模式与 keepalive 参数化（MA-3、MA-4），依赖 1
4. `hz-android` JNI 桥、Android `Platform`、VpnService 生命周期与最小可连通 App（MA-5、MA-6），依赖 1–3
5. Compose UI 全量：状态、对端、引导、深链（MA-7）
6. 通知与诊断包（MA-8）
7. APK 签名、coord 分发、App 内更新、CI（MA-9、MA-10）
8. 文档：安装手册 Android 章节、`android-smoke-test.md`、runbook 中的 keystore 保管；发布 `0.4.0`

## 13. 验收

- [ ] 一台未装过 HzNet 的 Android 9+ arm64 手机，从 coord 下载 APK 安装，经浏览器登录或邀请码加入，能与 Linux Node 按 Node Address 与 `<name>.hznet.internal` 互通
- [ ] HzNet 开启期间，手机上其他 App 的上网与 DNS 解析不受影响
- [ ] 重启手机后保持原 Desired State：`down` 仍断开，`up` 自动连接
- [ ] 另一个 VPN 抢占后，App 显示"被其他 VPN 接管"并收到通知
- [ ] Wi-Fi 与蜂窝互切后 30 秒内恢复与对端的通信
- [ ] 其他 Node 能按 Policy 访问手机上开放的端口，Policy 未允许的端口不通
- [ ] 身份到期前 3 天、1 天收到通知，点"重新登录"可续期
- [ ] 诊断包不含私钥、Auth Key、邀请码与登录 token
- [ ] App 能从 coord 发现新版 APK，User 确认后升级，Node Name 与 Node Address 不变
- [ ] Linux / macOS 现有 Seam A、Seam B 全绿
