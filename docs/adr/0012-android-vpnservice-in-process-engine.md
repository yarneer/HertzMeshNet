# Android 用 VpnService 承载进程内引擎，接受与其他 VPN 互斥

Android Client App 不跑 root 守护进程：数据面引擎（`hz-engine`，经 JNI 嵌入）运行在 App 的 `VpnService` 进程内，TUN fd、路由与 DNS 都由 `VpnService.Builder` 声明，外层 socket 经 `VpnService.protect` 绕开隧道。界面用 Kotlin + Jetpack Compose，与引擎之间的契约沿用 hzd IPC 的 JSON 语义（status 快照、`subscribe`、`up` / `down` / `login_poll` / `diagnostics`），以 `clients/fixtures/` 做契约测试。

代价是 Android 同一时间只允许一个 VpnService：开启 HzNet 会顶掉其他 VPN / 代理类 App，桌面端已实测的"与其他 TUN 类工具共存"在 Android 上做不到。曾考虑要求 root 后跑 hzd 二进制，可保留共存能力，但组织里几乎没有 root 过的手机；也曾考虑 Flutter 或 Tauri mobile 复用 UI，但与 [ADR-0010](0010-client-app-as-gui-shell.md) 一样，各平台共享的应是引擎与契约而非界面。被抢占（`onRevoke`）时 App 把 Desired State 写为 `down` 并明确提示，而不是静默重连去抢回。
