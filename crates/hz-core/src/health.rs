//! Health Report（#69 v0.3 / 规格 §3、§4）：hzd 每 30 秒随 ReportEndpoints
//! 上报的本机结论。Relay 原因判定是纯函数（输入为本机 netcheck 状态与该
//! 对端的打洞/握手观察），表驱动可全平台单测；探测数据复用 #65 netcheck
//! 已有的状态采集，不重复实现。

/// NAT 形态（#76）：两个 STUN 目标映射端口相同 = easy（端点无关），
/// 不同 = hard（端点相关，对称型），只有一个目标成功 = unknown。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatKind {
    Easy,
    Hard,
    Unknown,
}

impl NatKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NatKind::Easy => "easy",
            NatKind::Hard => "hard",
            NatKind::Unknown => "unknown",
        }
    }
}

/// 两个 STUN 目标映射端口 → NAT 形态。端口数不足两个时不猜测。
pub fn nat_kind(mapped_ports: &[u16]) -> NatKind {
    match mapped_ports {
        [] | [_] => NatKind::Unknown,
        ports if ports.iter().all(|port| *port == ports[0]) => NatKind::Easy,
        _ => NatKind::Hard,
    }
}

/// 单个 Relayed 对端的原因判定输入（规格 §4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayReasonInput {
    /// 本机 `udp4_ok || udp6_ok`。
    pub local_udp_ok: bool,
    /// 对端在 Network Map 中有任意可用候选 Endpoint。
    pub peer_has_candidates: bool,
    /// 打洞信令已往来：收到过对端的 PunchAck（双方都朝候选出过洞）。
    pub signaling_exchanged: bool,
    /// 直连接收新鲜（有对端直达的 WireGuard 报文）。
    pub direct_rx_fresh: bool,
}

/// Relay 原因（协议字符串，跨 hzd/coord/Admin Console 的稳定契约）。
pub const REASON_LOCAL_UDP_BROKEN: &str = "local_udp_broken";
pub const REASON_NO_CANDIDATES: &str = "no_candidates";
pub const REASON_HANDSHAKE_TIMEOUT: &str = "handshake_timeout";
pub const REASON_PUNCH_PENDING: &str = "punch_pending";

/// Relay 原因，按序取第一条命中（规格 §4 表）：
/// `local_udp_broken` → `no_candidates` → `handshake_timeout` → `punch_pending`。
/// 只有 `punch_pending` 不计入健康圆点黄色条件（它也是尚未出结论时的兜底，
/// 含对端刚出现在 Map 里、打洞还没发起的情况）。
pub fn relay_reason(input: &RelayReasonInput) -> &'static str {
    if !input.local_udp_ok {
        REASON_LOCAL_UDP_BROKEN
    } else if !input.peer_has_candidates {
        REASON_NO_CANDIDATES
    } else if input.signaling_exchanged && !input.direct_rx_fresh {
        REASON_HANDSHAKE_TIMEOUT
    } else {
        REASON_PUNCH_PENDING
    }
}

/// 一个 Relayed 对端（Health Report 的 `relayed_peers` 元素）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayedPeerNote {
    pub node_id: String,
    pub reason: &'static str,
}

/// 一次 Health Report 的全部字段（规格 §3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSnapshot {
    pub udp4_ok: bool,
    pub udp6_ok: bool,
    pub has_stun_mapping: bool,
    pub nat: NatKind,
    pub default_route_virtual: bool,
    pub suspicious_endpoint: bool,
    pub direct_peers: u32,
    pub relayed_peers: Vec<RelayedPeerNote>,
}

impl HealthSnapshot {
    pub fn to_proto(&self) -> hz_proto::HealthReport {
        hz_proto::HealthReport {
            udp4_ok: self.udp4_ok,
            udp6_ok: self.udp6_ok,
            has_stun_mapping: self.has_stun_mapping,
            nat: self.nat.as_str().to_string(),
            default_route_virtual: self.default_route_virtual,
            suspicious_endpoint: self.suspicious_endpoint,
            direct_peers: self.direct_peers,
            relayed_peers: self
                .relayed_peers
                .iter()
                .map(|peer| hz_proto::RelayedPeer {
                    node_id: peer.node_id.clone(),
                    reason: peer.reason.to_string(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> RelayReasonInput {
        RelayReasonInput {
            local_udp_ok: true,
            peer_has_candidates: true,
            signaling_exchanged: false,
            direct_rx_fresh: false,
        }
    }

    /// 规格 §4 每条一行 + 多条同时满足取优先级最高者。
    #[test]
    fn relay_reason_follows_the_spec_order() {
        // #63：本机双栈 UDP 全断，无论对端状态如何都判 local_udp_broken。
        let mut broken = input();
        broken.local_udp_ok = false;
        broken.peer_has_candidates = false;
        broken.signaling_exchanged = true;
        assert_eq!(relay_reason(&broken), "local_udp_broken");

        // 对端没有任何候选（旧版 hzd / STUN 失败且不在同一局域网）。
        let mut no_candidates = input();
        no_candidates.peer_has_candidates = false;
        assert_eq!(relay_reason(&no_candidates), "no_candidates");

        // 信令已往来、对端出过洞，但 WireGuard 握手超时（安全组未放行）。
        let mut timeout = input();
        timeout.signaling_exchanged = true;
        assert_eq!(relay_reason(&timeout), "handshake_timeout");

        // 已尝试、尚无结论（启动后最初 30 秒）；尚未发起打洞时同样兜底到它。
        assert_eq!(relay_reason(&input()), "punch_pending");
        assert_eq!(
            relay_reason(&RelayReasonInput {
                signaling_exchanged: false,
                ..input()
            }),
            REASON_PUNCH_PENDING
        );
        assert_eq!(REASON_HANDSHAKE_TIMEOUT, "handshake_timeout");

        // 多条同时满足：本机 UDP 断 + 信令往来 + 无候选 → 第一条命中。
        let mut stacked = input();
        stacked.local_udp_ok = false;
        stacked.peer_has_candidates = false;
        stacked.signaling_exchanged = true;
        assert_eq!(relay_reason(&stacked), "local_udp_broken");

        // 无候选优先于握手超时：没有候选就谈不上握手。
        let mut stacked = input();
        stacked.peer_has_candidates = false;
        stacked.signaling_exchanged = true;
        assert_eq!(relay_reason(&stacked), "no_candidates");
    }

    #[test]
    fn nat_kind_same_ports_easy_different_hard_single_unknown() {
        assert_eq!(nat_kind(&[]), NatKind::Unknown);
        assert_eq!(nat_kind(&[51820]), NatKind::Unknown);
        assert_eq!(nat_kind(&[51820, 51820]), NatKind::Easy);
        assert_eq!(nat_kind(&[51820, 9543]), NatKind::Hard);
        assert_eq!(nat_kind(&[51820, 51820, 9543]), NatKind::Hard);
        assert_eq!(NatKind::Hard.as_str(), "hard");
    }

    #[test]
    fn snapshot_maps_onto_proto_fields() {
        let snapshot = HealthSnapshot {
            udp4_ok: true,
            udp6_ok: false,
            has_stun_mapping: true,
            nat: NatKind::Hard,
            default_route_virtual: false,
            suspicious_endpoint: false,
            direct_peers: 1,
            relayed_peers: vec![RelayedPeerNote {
                node_id: "n-2".to_string(),
                reason: "handshake_timeout",
            }],
        };
        let proto = snapshot.to_proto();
        assert!(proto.udp4_ok);
        assert!(!proto.udp6_ok);
        assert!(proto.has_stun_mapping);
        assert_eq!(proto.nat, "hard");
        assert_eq!(proto.direct_peers, 1);
        assert_eq!(proto.relayed_peers.len(), 1);
        assert_eq!(proto.relayed_peers[0].node_id, "n-2");
        assert_eq!(proto.relayed_peers[0].reason, "handshake_timeout");
    }
}
