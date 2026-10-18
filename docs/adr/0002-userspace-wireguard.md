# 数据面使用用户态 WireGuard，而非内核 WireGuard

Node 守护进程在用户态运行 WireGuard（基于 `boringtun`）并通过 TUN 设备收发流量，而不是用 netlink 配置内核 WireGuard。NAT 穿透要求打洞用的 UDP socket 与 WireGuard 收发数据的 socket 是同一个，并且要能在直连与 Relay 之间随时切换端点；内核实现做不到这一点，且 macOS 没有内核实现。我们接受用户态带来的吞吐与 CPU 开销，请不要为了性能把它"优化"回内核 WireGuard。
