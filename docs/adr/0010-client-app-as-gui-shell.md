# macOS Client App 是 hzd 之上的 GUI 外壳，Network Extension 推迟

macOS Client App（SwiftUI 菜单栏 App）只做界面：数据面仍是现有的 `hzd`（root 守护进程、`boringtun`、utun），App 经 `/var/run/hzd.sock` 的 JSON-lines IPC 与它通信。`hzd` 与 `hz` 内置在 App bundle 里，由 `SMAppService` 注册为 LaunchDaemon，Developer ID 签名并公证后以 `.dmg` 分发。App 内的后端访问封装在一层薄接口之后，将来若改走 Network Extension，只换后端、不重写界面。

曾考虑直接把 Rust 核心经 FFI 嵌进 `NEPacketTunnelProvider`：可上 Mac App Store、不需要 root 守护进程，也为 iOS 铺路。但它要重写 utun、路由与 DNS 这层平台代码，而且隧道类 Network Extension 之间基本互斥，会丢掉与其他 TUN 类网络工具共存这一已实测的能力（[mvp-spec §8](../mvp-spec.md)）。也曾考虑用 Tauri 复用 Rust 代码，但 SMAppService、通知、深链等系统集成都要自己桥接，而共享给将来 Windows 客户端的应是 IPC 契约而非 UI 代码，因此选 SwiftUI。Network Extension 等到要做 iOS 时再议。
