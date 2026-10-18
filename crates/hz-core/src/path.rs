//! 路径选择（FR-8）：每个对端一个状态机。Relayed 起步（保证连通优先），
//! 打洞成功升级 Direct（IPv6 候选先试），直连接收静默超过 [`DIRECT_RX_FRESH`]
//! 后退回 Relayed 并按退避继续重试升级。输入是 Network Map 的对端 Endpoint、
//! 引擎直连接收的新鲜度与时钟；输出是 [`PathEvent`]，由装配层（hzd）执行。
//! 本模块不碰网络，可全平台单测。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// 直连接收的新鲜窗口：超过它没从对端收到直达的 WireGuard 报文就判直连失效。
/// 必须大于引擎的保活间隔（8s），否则空闲直连会被误判为失效。
pub const DIRECT_RX_FRESH: Duration = Duration::from_secs(10);

/// 打洞重试起步间隔与上限：Relayed 状态下按此节奏重试升级。
const RETRY_START: Duration = Duration::from_secs(2);
const RETRY_CAP: Duration = Duration::from_secs(30);

/// Network Map 里一个对端的候选 Endpoint，按来源分组。
#[derive(Debug, Clone, Default)]
pub struct PeerEndpoints {
    pub node_id: String,
    pub v6: Vec<SocketAddr>,
    pub stun: Vec<SocketAddr>,
    pub lan: Vec<SocketAddr>,
}

impl PeerEndpoints {
    /// 尝试顺序：V6 优先，Stun 次之，Lan 兜底。
    pub fn ranked(&self) -> Vec<SocketAddr> {
        let mut all = Vec::with_capacity(self.v6.len() + self.stun.len() + self.lan.len());
        all.extend(
            self.v6
                .iter()
                .chain(self.stun.iter())
                .chain(self.lan.iter()),
        );
        all
    }

    fn has_candidate(&self) -> bool {
        !(self.v6.is_empty() && self.stun.is_empty() && self.lan.is_empty())
    }
}

/// 路径状态机的一次输出，由装配层执行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathEvent {
    /// 切换该对端的传输开关（true = 走 Relay）。
    SetUseRelay { node_id: String, use_relay: bool },
    /// 朝对端候选 Endpoint 发 WireGuard 握手（打洞包，同时打开双方 NAT）。
    SendHandshake { node_id: String },
    /// 经 Relay 发 PunchOffer（携带本机候选）。
    SendOffer { node_id: String },
    /// 经 Relay 回 PunchAck（选定候选）。
    SendAck { node_id: String, chosen: SocketAddr },
}

struct PeerPath {
    direct: bool,
    last_attempt: Option<Instant>,
    retry: Duration,
}

#[derive(Default)]
pub struct PathManager {
    peers: HashMap<String, PeerPath>,
}

impl PathManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// 推进一次状态机。direct_rx_ages 是各对端最近一次直连接收距今的时间
    /// （None = 从未）。now 由调用方注入以便测试。
    pub fn tick(
        &mut self,
        now: Instant,
        peers: &[PeerEndpoints],
        direct_rx_ages: &HashMap<String, Option<Duration>>,
    ) -> Vec<PathEvent> {
        let live: Vec<&str> = peers.iter().map(|peer| peer.node_id.as_str()).collect();
        self.peers
            .retain(|node_id, _| live.contains(&node_id.as_str()));
        let mut events = Vec::new();
        for peer in peers {
            let candidate = self.peers.entry(peer.node_id.clone()).or_insert(PeerPath {
                direct: false,
                last_attempt: None,
                retry: RETRY_START,
            });
            let direct_fresh = direct_rx_ages
                .get(&peer.node_id)
                .and_then(|age| *age)
                .is_some_and(|age| age <= DIRECT_RX_FRESH);
            if candidate.direct {
                if direct_fresh {
                    continue;
                }
                candidate.direct = false;
                candidate.retry = RETRY_START;
                candidate.last_attempt = Some(now);
                events.push(PathEvent::SetUseRelay {
                    node_id: peer.node_id.clone(),
                    use_relay: true,
                });
                continue;
            }
            if direct_fresh {
                candidate.direct = true;
                candidate.retry = RETRY_START;
                events.push(PathEvent::SetUseRelay {
                    node_id: peer.node_id.clone(),
                    use_relay: false,
                });
                continue;
            }
            if !peer.has_candidate() {
                continue;
            }
            let due = candidate
                .last_attempt
                .is_none_or(|at| now.duration_since(at) >= candidate.retry);
            if due {
                candidate.last_attempt = Some(now);
                candidate.retry = (candidate.retry * 2).min(RETRY_CAP);
                events.push(PathEvent::SendOffer {
                    node_id: peer.node_id.clone(),
                });
                events.push(PathEvent::SendHandshake {
                    node_id: peer.node_id.clone(),
                });
            }
        }
        events
    }

    /// 收到对端信令（Offer 或 Ack）后的记账：重置重试节奏，让应答的握手
    /// 立刻发出而不是等下一轮退避。
    pub fn note_punch_signal(&mut self, node_id: &str, now: Instant) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.last_attempt = Some(now);
            peer.retry = RETRY_START;
        }
    }

    /// 当前路径形态（true = Direct）；未知对端按 Relayed。
    pub fn is_direct(&self, node_id: &str) -> bool {
        self.peers.get(node_id).is_some_and(|peer| peer.direct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints(id: &str) -> PeerEndpoints {
        PeerEndpoints {
            node_id: id.to_string(),
            v6: vec![],
            stun: vec!["203.0.113.9:41001".parse().unwrap()],
            lan: vec![],
        }
    }

    fn ages(id: &str, age: Option<u64>) -> HashMap<String, Option<Duration>> {
        HashMap::from([(id.to_string(), age.map(Duration::from_secs))])
    }

    #[test]
    fn starts_relayed_then_upgrades_on_direct_rx() {
        let id = "n1";
        let mut manager = PathManager::new();
        let start = Instant::now();
        let first = manager.tick(start, &[endpoints(id)], &ages(id, None));
        assert_eq!(
            first,
            vec![
                PathEvent::SendOffer { node_id: id.into() },
                PathEvent::SendHandshake { node_id: id.into() },
            ]
        );
        let second = manager.tick(start, &[endpoints(id)], &ages(id, Some(0)));
        assert_eq!(
            second,
            vec![PathEvent::SetUseRelay {
                node_id: id.into(),
                use_relay: false
            }]
        );
        assert!(manager.is_direct(id));
        // 直连保持新鲜：不再产生事件。
        assert!(
            manager
                .tick(
                    start + Duration::from_secs(1),
                    &[endpoints(id)],
                    &ages(id, Some(0))
                )
                .is_empty()
        );
    }

    #[test]
    fn stale_direct_rx_reverts_to_relay_with_retry_backoff() {
        let id = "n2";
        let mut manager = PathManager::new();
        let start = Instant::now();
        manager.tick(start, &[endpoints(id)], &ages(id, Some(0)));
        let reverted = manager.tick(
            start + DIRECT_RX_FRESH + Duration::from_secs(1),
            &[endpoints(id)],
            &ages(id, Some(60)),
        );
        assert_eq!(
            reverted,
            vec![PathEvent::SetUseRelay {
                node_id: id.into(),
                use_relay: true
            }]
        );
        assert!(!manager.is_direct(id));
        // 退避期内的推进不再重试；窗口过后才再次发信令。
        let during_backoff = manager.tick(
            start + DIRECT_RX_FRESH + Duration::from_secs(2),
            &[endpoints(id)],
            &ages(id, Some(60)),
        );
        assert!(during_backoff.is_empty());
        let after_backoff = manager.tick(
            start + DIRECT_RX_FRESH + Duration::from_secs(3),
            &[endpoints(id)],
            &ages(id, Some(60)),
        );
        assert_eq!(
            after_backoff,
            vec![
                PathEvent::SendOffer { node_id: id.into() },
                PathEvent::SendHandshake { node_id: id.into() },
            ]
        );
    }

    #[test]
    fn vanished_peer_state_is_dropped() {
        let mut manager = PathManager::new();
        let start = Instant::now();
        manager.tick(start, &[endpoints("gone")], &ages("gone", Some(0)));
        manager.tick(start, &[], &HashMap::new());
        assert!(!manager.is_direct("gone"));
    }

    #[test]
    fn peer_without_candidates_never_punches() {
        let mut manager = PathManager::new();
        let events = manager.tick(
            Instant::now(),
            &[PeerEndpoints {
                node_id: "n3".into(),
                ..Default::default()
            }],
            &HashMap::new(),
        );
        assert!(events.is_empty());
    }

    #[test]
    fn ranked_candidates_put_v6_first() {
        let peer = PeerEndpoints {
            node_id: "n4".into(),
            v6: vec!["[2001:db8::1]:51820".parse().unwrap()],
            stun: vec!["203.0.113.2:40001".parse().unwrap()],
            lan: vec!["192.168.1.2:51820".parse().unwrap()],
        };
        assert_eq!(
            peer.ranked(),
            vec![
                "[2001:db8::1]:51820".parse().unwrap(),
                "203.0.113.2:40001".parse().unwrap(),
                "192.168.1.2:51820".parse().unwrap(),
            ]
        );
    }
}
