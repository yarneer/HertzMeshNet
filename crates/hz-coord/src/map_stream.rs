//! Network Map 推送枢纽（FR-6 / #6）：登记每条打开的下发流，单一 fan-out 任务
//! 在存储变更、周期清扫（到期跨越）或保活到期时重建全量快照、对上一版做差量，
//! 按流投递（新流先收全量，之后收差量）。断线的流在投递失败时从登记表移除。
//! Policy 过滤（#13、ADR-0006）落在快照构建处，本模块不做过滤。

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hz_proto::network_map_message::Kind;
use hz_proto::{MapDelta, NetworkMap, NetworkMapMessage, NodeInfo};
use tokio::sync::{Notify, mpsc};

use crate::store::{NodeRecord, Store};

/// 每条下发流的待发队列深度；慢消费者队列打满时改走全量重同步（见 deliver）。
const STREAM_BUFFER: usize = 16;

pub struct MapPushConfig {
    /// 空差量保活间隔（兼作对端读超时探测）。
    pub keepalive_every: Duration,
    /// 全量重建间隔：接住绕过 notify 的到期跨越等外部写入。
    pub sweep_every: Duration,
}

struct Subscriber {
    tx: mpsc::Sender<Result<NetworkMapMessage, tonic::Status>>,
    /// 登记后尚未发过全量；下一轮投递先补全量再转差量。
    needs_full: bool,
}

/// 打开中的下发流登记表 + 唤醒信号。
pub struct MapHub {
    subscribers: Mutex<HashMap<String, Subscriber>>,
    wake: Notify,
}

impl Default for MapHub {
    fn default() -> Self {
        Self::new()
    }
}

impl MapHub {
    pub fn new() -> Self {
        Self {
            subscribers: Mutex::new(HashMap::new()),
            wake: Notify::new(),
        }
    }

    /// 登记一条新流（同 Node 重复打开时新流替换旧流）并唤醒推送任务补发全量。
    pub fn register(
        &self,
        node_id: String,
    ) -> mpsc::Receiver<Result<NetworkMapMessage, tonic::Status>> {
        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        self.subscribers.lock().expect("map hub poisoned").insert(
            node_id,
            Subscriber {
                tx,
                needs_full: true,
            },
        );
        self.wake.notify_one();
        rx
    }

    /// 打开中的下发流数（在线 Node 数，FR-12 指标用）。
    pub fn online_nodes(&self) -> usize {
        self.subscribers.lock().expect("map hub poisoned").len()
    }
}

/// 推送主循环：单写者。任何流的首条消息都从这里发出（全量），
/// 之后同一条流上只会出现按时间序计算的差量，不存在"旧差量覆盖新全量"的乱序。
pub async fn run_fan_out(store: Store, hub: Arc<MapHub>, config: MapPushConfig) {
    let mut changes = store.changes();
    let mut previous: Option<Vec<NodeRecord>> = None;
    let mut sweep = tokio::time::interval(config.sweep_every);
    let mut keepalive = tokio::time::interval(config.keepalive_every);
    loop {
        let keepalive_due = tokio::select! {
            _ = changes.changed() => false,
            _ = sweep.tick() => false,
            _ = keepalive.tick() => true,
            _ = hub.wake.notified() => false,
        };
        let current = match store.network_map().await {
            Ok(nodes) => nodes,
            Err(error) => {
                tracing::error!(%error, "build network map failed");
                continue;
            }
        };
        deliver(&hub, &current, previous.as_deref(), keepalive_due);
        previous = Some(current);
    }
}

fn delta_message(added: Vec<NodeInfo>, removed: Vec<String>) -> NetworkMapMessage {
    NetworkMapMessage {
        kind: Some(Kind::Delta(MapDelta {
            added_or_updated: added,
            removed_node_ids: removed,
        })),
    }
}

/// 全量快照的差量：内容变化或新增的进 added_or_updated，消失的进 removed。
fn diff(previous: &[NodeRecord], current: &[NodeRecord]) -> Option<MapDelta> {
    let prev_by_id: HashMap<&str, &NodeRecord> =
        previous.iter().map(|r| (r.id.as_str(), r)).collect();
    let current_ids: HashSet<&str> = current.iter().map(|r| r.id.as_str()).collect();
    let added_or_updated = current
        .iter()
        .filter(|r| prev_by_id.get(r.id.as_str()) != Some(r))
        .map(|r| node_info_from(r.clone()))
        .collect::<Vec<_>>();
    let removed_node_ids = previous
        .iter()
        .filter(|r| !current_ids.contains(r.id.as_str()))
        .map(|r| r.id.clone())
        .collect::<Vec<_>>();
    if added_or_updated.is_empty() && removed_node_ids.is_empty() {
        None
    } else {
        Some(MapDelta {
            added_or_updated,
            removed_node_ids,
        })
    }
}

fn deliver(
    hub: &MapHub,
    current: &[NodeRecord],
    previous: Option<&[NodeRecord]>,
    keepalive_due: bool,
) {
    let delta = previous.and_then(|previous| diff(previous, current));
    let mut subscribers = hub.subscribers.lock().expect("map hub poisoned");
    subscribers.retain(|node_id, subscriber| {
        let message = if subscriber.needs_full {
            NetworkMapMessage {
                kind: Some(Kind::Full(NetworkMap {
                    nodes: current.iter().cloned().map(node_info_from).collect(),
                })),
            }
        } else if let Some(delta) = &delta {
            delta_message(
                delta.added_or_updated.clone(),
                delta.removed_node_ids.clone(),
            )
        } else if keepalive_due {
            delta_message(Vec::new(), Vec::new())
        } else {
            return true;
        };
        match subscriber.tx.try_send(Ok(message)) {
            Ok(()) => {
                subscriber.needs_full = false;
                true
            }
            // 队列打满说明这条流消费不动；标回待全量，下轮直接全量重同步。
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(%node_id, "map stream backpressured, will resync with full map");
                subscriber.needs_full = true;
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!(%node_id, "map stream receiver dropped");
                false
            }
        }
    });
}

pub fn node_info_from(record: NodeRecord) -> NodeInfo {
    let detailed = record
        .udp_endpoints
        .iter()
        .filter_map(|stored| {
            let addr: std::net::SocketAddr = stored.addr.parse().ok()?;
            let kind = match stored.kind.as_str() {
                "stun" => hz_proto::EndpointKind::Stun,
                "v6" => hz_proto::EndpointKind::V6,
                _ => hz_proto::EndpointKind::Lan,
            };
            Some(hz_proto::Endpoint {
                addr: addr.ip().to_string(),
                port: addr.port() as u32,
                kind: kind as i32,
            })
        })
        .collect::<Vec<_>>();
    NodeInfo {
        node_id: record.id,
        name: record.name,
        ipv4: record.ipv4.to_string(),
        ipv6: record.ipv6.to_string(),
        tags: record.tags,
        owner_user: record.owner_user,
        expires_at_unix: record.expires_at_unix,
        node_key_pub: record.node_key_pub,
        endpoints: record
            .udp_endpoints
            .iter()
            .map(|stored| stored.addr.clone())
            .collect(),
        detailed_endpoints: detailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, endpoints: &[(&str, &str)]) -> NodeRecord {
        NodeRecord {
            id: id.to_string(),
            name: format!("node-{id}"),
            ipv4: format!("100.96.0.{id}").parse().unwrap(),
            ipv6: format!("fd00::96:0:0:{id}").parse().unwrap(),
            tags: vec![],
            owner_user: None,
            expires_at_unix: None,
            node_key_pub: vec![1u8; 32],
            udp_endpoints: endpoints
                .iter()
                .map(|(addr, kind)| crate::store::StoredEndpoint::of_kind(*addr, kind))
                .collect(),
        }
    }

    #[test]
    fn diff_reports_added_changed_and_removed() {
        let a = record("1", &[("10.0.0.1:1", "lan")]);
        let a_moved = record("1", &[("10.0.0.9:9", "lan")]);
        let b = record("2", &[]);

        let delta = diff(std::slice::from_ref(&a), std::slice::from_ref(&a));
        assert!(delta.is_none(), "无变化不产生差量：{delta:?}");

        let delta = diff(std::slice::from_ref(&a), &[a_moved.clone(), b.clone()]).unwrap();
        assert_eq!(delta.removed_node_ids, Vec::<String>::new());
        assert_eq!(delta.added_or_updated.len(), 2);

        let delta = diff(&[a.clone(), b.clone()], std::slice::from_ref(&a)).unwrap();
        assert_eq!(delta.removed_node_ids, vec!["2".to_string()]);
        assert!(delta.added_or_updated.is_empty());
    }

    #[test]
    fn node_info_carries_legacy_and_detailed_endpoint_views() {
        let info = node_info_from(record(
            "7",
            &[
                ("203.0.113.5:41001", "stun"),
                ("192.168.1.2:51820", "lan"),
                ("[2001:db8::2]:51820", "v6"),
            ],
        ));
        assert_eq!(
            info.endpoints,
            vec![
                "203.0.113.5:41001".to_string(),
                "192.168.1.2:51820".to_string(),
                "[2001:db8::2]:51820".to_string(),
            ]
        );
        assert_eq!(info.detailed_endpoints.len(), 3);
        assert_eq!(
            info.detailed_endpoints[0].kind,
            hz_proto::EndpointKind::Stun as i32
        );
        assert_eq!(
            info.detailed_endpoints[1].kind,
            hz_proto::EndpointKind::Lan as i32
        );
        assert_eq!(
            info.detailed_endpoints[2].kind,
            hz_proto::EndpointKind::V6 as i32
        );
        assert_eq!(info.detailed_endpoints[2].addr, "2001:db8::2");
        assert_eq!(info.detailed_endpoints[2].port, 51820);
    }
}
