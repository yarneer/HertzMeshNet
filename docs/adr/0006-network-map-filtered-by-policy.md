# Network Map 只包含 Policy 相关的 Node，打洞信令走 Relay

Coordination Server 下发给某个 Node 的 Network Map 只包含 Policy 允许它访问或允许访问它的 Node，而不是整个 HzNet：被攻破的设备拿不到整张网络的拓扑，也减少了下发量，代价是 Policy 一变就要重算受影响 Node 的 Network Map。打洞所需的实时 Endpoint 协商通过 Relay 通道传递，且用 Node Key 端到端加密，Coordination Server 不参与，因此其负载与打洞频率无关。
