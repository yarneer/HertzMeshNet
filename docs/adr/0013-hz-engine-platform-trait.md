# 从 hzd 抽出 hz-engine，平台能力经 Platform trait 注入

`hzd` 中的编排逻辑（会话与注册、登录轮询、Network Map 流、数据面监督、Endpoint 与 Relay、netcheck、Health Report、`diagnostics`、请求分发）抽成平台无关的 `hz-engine` crate；平台相关能力收敛为一个 `Platform` trait 的四个方法：`establish`（一次性提交地址、路由、DNS、MTU 并返回 TUN fd）、`protect`（外层 socket 绕开隧道）、`net_events`（物理网络变化）、`system_dns`。`hzd` 只保留桌面专属部分（UDS IPC 与 uid 分档、launchd / systemd、路由守护与冲突检测、系统 DNS 接入、Port Map），配置由环境变量解析为 `EngineConfig` 后传入。

`establish` 采用原子语义，是照着 Android `VpnService.Builder.establish()` 定的：桌面可以把"建 tun → 配路由 → 接 DNS"包成一步，反过来 Android 却无法拆成多步。曾考虑为 Android 另 fork 一份精简引擎（快，但两份代码必然漂移），或继续在现有模块里加 `cfg(target_os = "android")`（`hzd/src/lib.rs` 已逾 130K，再堆分支更难维护）。抽引擎也为将来的 Windows 与 iOS（Network Extension）铺路：新平台只需实现 `Platform`。
