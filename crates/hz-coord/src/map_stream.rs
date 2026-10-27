//! Network Map 推送枢纽（FR-6 / #6 / #13）：登记每条打开的下发流，单一
//! fan-out 任务在存储变更、周期清扫（到期跨越）、Policy 变更或保活到期时
//! 重建快照、对每个订阅者计算**各自的过滤视图**（ADR-0006 + FR-10）并差量
//! 投递（新流先收全量，之后收差量）。Policy 存在时，订阅者只能看见与它
//! 被任一规则连通的 Node；自己永远可见（本机 DNS 解析自己的名字）。
//! 断线的流在投递失败时从登记表移除。

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hz_core::policy::{InboundRule, PolicyDoc};
use hz_proto::network_map_message::Kind;
use hz_proto::{MapDelta, NetworkMap, NetworkMapMessage, NodeInfo, PolicyView};
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

/// 一个订阅者已下发的最后视图：差量与 Policy 变更判定都基于它。
struct Subscriber {
    tx: mpsc::Sender<Result<NetworkMapMessage, tonic::Status>>,
    /// 登记后尚未发过全量；下一轮投递先补全量再转差量。
    needs_full: bool,
    last_view: Vec<NodeRecord>,
    /// 最近一次随消息下发的 Policy 视图（版本 + 入站规则），None = 从未发过。
    last_policy: Option<(i64, Vec<InboundRule>)>,
    /// 登记纪元（hub 级递增）：全量必须由登记之后的快照发出。
    epoch: u64,
}

/// 打开中的下发流登记表 + 唤醒信号。
pub struct MapHub {
    subscribers: Mutex<HashMap<String, Subscriber>>,
    wake: Notify,
    /// 登记纪元：每次 register 递增，用于全量快照的新鲜度判定。
    epoch: std::sync::atomic::AtomicU64,
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
            epoch: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn current_epoch(&self) -> u64 {
        self.epoch.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// 登记一条新流（同 Node 重复打开时新流替换旧流）并唤醒推送任务补发全量。
    pub fn register(
        &self,
        node_id: String,
    ) -> mpsc::Receiver<Result<NetworkMapMessage, tonic::Status>> {
        let (tx, rx) = mpsc::channel(STREAM_BUFFER);
        let epoch = self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        self.subscribers.lock().expect("map hub poisoned").insert(
            node_id,
            Subscriber {
                tx,
                needs_full: true,
                last_view: Vec::new(),
                last_policy: None,
                epoch,
            },
        );
        self.wake.notify_one();
        rx
    }

    /// 打开中的下发流数（在线 Node 数，FR-12 指标用）。
    pub fn online_nodes(&self) -> usize {
        self.subscribers.lock().expect("map hub poisoned").len()
    }

    /// 该 Node 是否有打开中的 Network Map 下发流。
    pub fn is_online(&self, node_id: &str) -> bool {
        self.subscribers
            .lock()
            .expect("map hub poisoned")
            .contains_key(node_id)
    }
}

/// 一轮推送的输入快照：全部在册 Node + 当前 Policy（None = 尚无 Policy，
/// bootstrap 全互通）。
struct Snapshot {
    nodes: Vec<NodeRecord>,
    policy: Option<(i64, PolicyDoc)>,
}

/// 推送主循环：单写者。任何流的首条消息都从这里发出（全量），
/// 之后同一条流上只会出现按时间序计算的差量，不存在"旧差量覆盖新全量"的乱序。
/// Policy 变更走同一条 notify 通道，受影响 Node 在秒级收到新视图与入站规则。
pub async fn run_fan_out(store: Store, hub: Arc<MapHub>, config: MapPushConfig) {
    let mut changes = store.changes();
    let mut sweep = tokio::time::interval(config.sweep_every);
    // interval() 的首个 tick 立即到期；select 分支随机选择会让它被推迟到
    // 任意后续轮次消费——可能在订阅者刚收到全量之后，凭空补发一条空保活
    // 差量（Linux CI 曾在 3600s 保活间隔下于开流数秒内收到）。interval_at
    // 把首次保活钉在启动 + keepalive_every，消除这个不定期提前保活。
    let mut keepalive = tokio::time::interval_at(
        tokio::time::Instant::now() + config.keepalive_every,
        config.keepalive_every,
    );
    loop {
        let keepalive_due = tokio::select! {
            _ = changes.changed() => false,
            _ = sweep.tick() => false,
            _ = keepalive.tick() => true,
            _ = hub.wake.notified() => false,
        };
        // 快照装载与流登记可能并发：记下装载前的登记纪元，deliver 对纪元
        // 更新的订阅者跳过本轮（它登记时已提交的变更可能不在本快照里，
        // 全量必须由更新鲜的快照补发），避免"旧数据当全量"。
        let epoch = hub.current_epoch();
        let snapshot = match load_snapshot(&store).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::error!(%error, "build network map snapshot failed");
                continue;
            }
        };
        deliver(&hub, &snapshot, epoch, keepalive_due);
    }
}

async fn load_snapshot(store: &Store) -> anyhow::Result<Snapshot> {
    let nodes = store.network_map().await?;
    let policy = match store.current_policy().await? {
        Some((version, content)) => {
            // 入库内容经过完整校验；此处再解析失败说明库被外部改写，
            // 记错并按无 Policy 对待（保持网络可用，管理员可重新 push）。
            match hz_core::policy::parse_policy(&content) {
                Ok(doc) => Some((version, doc)),
                Err(reason) => {
                    tracing::error!(%reason, version, "stored policy no longer parses");
                    None
                }
            }
        }
        None => None,
    };
    Ok(Snapshot { nodes, policy })
}

fn delta_message(
    added: Vec<NodeInfo>,
    removed: Vec<String>,
    policy: Option<PolicyView>,
) -> NetworkMapMessage {
    NetworkMapMessage {
        kind: Some(Kind::Delta(MapDelta {
            added_or_updated: added,
            removed_node_ids: removed,
        })),
        policy,
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

/// 节点身份的 Policy 视角：归属 User + Tag 列表。
fn identity_of(record: &NodeRecord) -> (Option<&str>, &[String]) {
    (record.owner_user.as_deref(), record.tags.as_slice())
}

/// 订阅者视角的可见集合：自己永远可见；其余按规则连通性（任一方向）。
fn visible_to<'a>(snapshot: &'a Snapshot, subscriber: &NodeRecord) -> Vec<&'a NodeRecord> {
    let Some((_, doc)) = &snapshot.policy else {
        return snapshot.nodes.iter().collect();
    };
    let me = identity_of(subscriber);
    snapshot
        .nodes
        .iter()
        .filter(|node| node.id == subscriber.id || doc.pair_connected(me, identity_of(node)))
        .collect()
}

/// 订阅者应收到的 Policy 视图（None = 无 Policy，不下发该字段）。
fn policy_view_for(snapshot: &Snapshot, subscriber: &NodeRecord) -> Option<PolicyView> {
    let (version, doc) = snapshot.policy.as_ref()?;
    let me = identity_of(subscriber);
    Some(PolicyView {
        version: *version,
        groups: doc
            .groups
            .iter()
            .map(|group| hz_proto::PolicyGroup {
                name: group.name.clone(),
                users: group.users.clone(),
            })
            .collect(),
        inbound_rules: doc
            .inbound_rules_for(me)
            .into_iter()
            .map(|rule| hz_proto::InboundRule {
                from: rule.from.to_text(),
                ports: rule.ports.iter().map(|p| *p as u32).collect(),
            })
            .collect(),
    })
}

/// InboundRule 的领域形态（协议消息的对照侧，last_policy 存这个避免二次解析）。
fn inbound_rules_of(view: &PolicyView) -> Vec<InboundRule> {
    view.inbound_rules
        .iter()
        .filter_map(|rule| {
            let from = hz_core::policy::PolicySubject::parse(&rule.from).map_err(|reason| {
                tracing::error!(%reason, from = %rule.from, "unparseable inbound rule from server");
            }).ok()?;
            Some(InboundRule {
                from,
                ports: rule.ports.iter().map(|p| *p as u16).collect(),
            })
        })
        .collect()
}

fn deliver(hub: &MapHub, snapshot: &Snapshot, loaded_epoch: u64, keepalive_due: bool) {
    let by_id: HashMap<&str, &NodeRecord> = snapshot
        .nodes
        .iter()
        .map(|record| (record.id.as_str(), record))
        .collect();
    let mut subscribers = hub.subscribers.lock().expect("map hub poisoned");
    subscribers.retain(|node_id, subscriber| {
        if subscriber.needs_full && subscriber.epoch > loaded_epoch {
            return true;
        }
        // 订阅者自己已不在册（吊销/到期）：视图清空，差量只含 removed。
        let me = by_id.get(node_id.as_str()).copied();
        let visible: Vec<NodeRecord> = match me {
            Some(me) => visible_to(snapshot, me).into_iter().cloned().collect(),
            None => Vec::new(),
        };
        let policy_view = me.and_then(|me| policy_view_for(snapshot, me));
        let policy_changed = match (&policy_view, &subscriber.last_policy) {
            (Some(view), Some((version, rules))) => {
                *version != view.version || *rules != inbound_rules_of(view)
            }
            (Some(_), None) | (None, Some(_)) => true,
            (None, None) => false,
        };
        let delta = if subscriber.needs_full {
            None
        } else {
            diff(&subscriber.last_view, &visible)
        };
        let message = if subscriber.needs_full {
            NetworkMapMessage {
                kind: Some(Kind::Full(NetworkMap {
                    nodes: visible.iter().cloned().map(node_info_from).collect(),
                })),
                policy: policy_view.clone(),
            }
        } else if let Some(delta) = delta {
            delta_message(
                delta.added_or_updated,
                delta.removed_node_ids,
                if policy_changed {
                    policy_view.clone()
                } else {
                    None
                },
            )
        } else if policy_changed {
            delta_message(Vec::new(), Vec::new(), policy_view.clone())
        } else if keepalive_due {
            delta_message(Vec::new(), Vec::new(), None)
        } else {
            return true;
        };
        match subscriber.tx.try_send(Ok(message)) {
            Ok(()) => {
                subscriber.needs_full = false;
                subscriber.last_view = visible;
                subscriber.last_policy = policy_view
                    .as_ref()
                    .map(|view| (view.version, inbound_rules_of(view)));
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

    fn owned_record(n: u8, owner: Option<&str>, tags: &[&str]) -> NodeRecord {
        let mut base = record(&n.to_string(), &[]);
        base.owner_user = owner.map(str::to_string);
        base.tags = tags.iter().map(|t| t.to_string()).collect();
        base
    }

    fn dev_db_snapshot() -> Snapshot {
        let doc = hz_core::policy::parse_policy(
            "[[group]]\nname = \"dev\"\nusers = [\"alice\"]\n\
             [[rule]]\nfrom = \"group:dev\"\nto = \"tag:db\"\nports = [5432]\n",
        )
        .unwrap();
        Snapshot {
            nodes: vec![
                owned_record(1, Some("alice"), &[]),
                owned_record(2, Some("bob"), &[]),
                owned_record(4, None, &["db"]),
            ],
            policy: Some((1, doc)),
        }
    }

    #[test]
    fn visible_to_self_is_al_present_and_rules_filter_peers() {
        let snapshot = dev_db_snapshot();
        let a = &snapshot.nodes[0];
        let b = &snapshot.nodes[1];
        let d = &snapshot.nodes[2];

        let a_names: Vec<&str> = visible_to(&snapshot, a)
            .into_iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(a_names, vec!["1", "4"], "dev 成员可见自己与 db，不见 bob");

        let b_names: Vec<&str> = visible_to(&snapshot, b)
            .into_iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(b_names, vec!["2"], "非 dev 成员只剩自己");

        let d_names: Vec<&str> = visible_to(&snapshot, d)
            .into_iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(
            d_names,
            vec!["1", "4"],
            "可见性方向无关：db 也看见 dev 成员"
        );
    }

    #[test]
    fn policy_view_carries_version_groups_and_my_inbound_rules() {
        let snapshot = dev_db_snapshot();
        let d = &snapshot.nodes[2];
        let view = policy_view_for(&snapshot, d).unwrap();
        assert_eq!(view.version, 1);
        assert_eq!(view.groups.len(), 1);
        assert_eq!(view.groups[0].name, "dev");
        assert_eq!(view.groups[0].users, vec!["alice".to_string()]);
        assert_eq!(view.inbound_rules.len(), 1);
        assert_eq!(view.inbound_rules[0].from, "group:dev");
        assert_eq!(view.inbound_rules[0].ports, vec![5432]);

        let a = &snapshot.nodes[0];
        let view = policy_view_for(&snapshot, a).unwrap();
        assert!(
            view.inbound_rules.is_empty(),
            "to 侧不命中 a 的规则不进 a 的入站集合"
        );
    }

    #[test]
    fn no_policy_means_full_mesh_without_policy_field() {
        let snapshot = Snapshot {
            nodes: vec![
                owned_record(1, Some("alice"), &[]),
                owned_record(2, None, &["db"]),
            ],
            policy: None,
        };
        let a = &snapshot.nodes[0];
        assert_eq!(visible_to(&snapshot, a).len(), 2, "无 Policy 全互通");
        assert!(policy_view_for(&snapshot, a).is_none());
    }
}
