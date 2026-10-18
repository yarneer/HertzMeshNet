# 全栈自研，不兼容 Tailscale 协议

我们用 Rust 自研 Coordination Server、Node 守护进程和 Relay，并自定控制协议，不去实现与官方 Tailscale 客户端兼容的控制面（即不做 Rust 版 Headscale）。项目目标是学习驱动、以真实可用为验收标准：兼容路线能白拿多平台客户端，但会把我们绑在一个非公开且持续演进的协议上，也跳过了我们最想掌握的数据面与 NAT 穿透部分。代价是每个平台的客户端都要自己做，所以第一阶段只支持 Linux/macOS。
