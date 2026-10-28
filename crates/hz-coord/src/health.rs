//! coord 侧的节点可观测性（#69 v0.3 / ADR-0009）：Health Report 只存内存
//! （键 node_id，附收到时间，90 秒未更新视为过期，重启即清空）；`last_seen`
//! 内存实时更新、由后台任务批量落库；健康圆点与版本状态是纯函数（规格 §6）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use crate::store::unix_now;

/// Health Report 的过期阈值：3 个上报周期（规格 §5）。
pub const REPORT_TTL: Duration = Duration::from_secs(90);

/// last_seen 后台落库的两个节奏：流断开后尽快落一次，在线期间 5 分钟一批。
pub const OFFLINE_FLUSH_EVERY: Duration = Duration::from_secs(5);
pub const ONLINE_FLUSH_EVERY: Duration = Duration::from_secs(5 * 60);

/// Health Report 的 coord 侧领域形态（`hz_proto::HealthReport` 的对照侧）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHealth {
    pub udp4_ok: bool,
    pub udp6_ok: bool,
    pub has_stun_mapping: bool,
    pub nat: String,
    pub default_route_virtual: bool,
    pub suspicious_endpoint: bool,
    pub direct_peers: u32,
    /// (node_id, reason)；reason 见规格 §4。
    pub relayed_peers: Vec<(String, String)>,
}

impl From<hz_proto::HealthReport> for NodeHealth {
    fn from(report: hz_proto::HealthReport) -> Self {
        NodeHealth {
            udp4_ok: report.udp4_ok,
            udp6_ok: report.udp6_ok,
            has_stun_mapping: report.has_stun_mapping,
            nat: report.nat,
            default_route_virtual: report.default_route_virtual,
            suspicious_endpoint: report.suspicious_endpoint,
            direct_peers: report.direct_peers,
            relayed_peers: report
                .relayed_peers
                .into_iter()
                .map(|peer| (peer.node_id, peer.reason))
                .collect(),
        }
    }
}

/// 收到的一份 Health Report 与收到时刻。
#[derive(Debug, Clone)]
pub struct ReceivedReport {
    pub report: NodeHealth,
    pub at: Instant,
}

/// Health Report 内存表 + last_seen / 运行时信息的写穿缓存。
/// 键为 node_id；coord 重启后为空（界面显示「等待上报」，ADR-0009）。
#[derive(Default)]
pub struct HealthCenter {
    reports: StdMutex<HashMap<String, ReceivedReport>>,
    last_seen: StdMutex<HashMap<String, i64>>,
    /// 尚未落库的 last_seen（note_seen 置脏，flush 任务取走）。
    dirty_last_seen: StdMutex<HashMap<String, i64>>,
    /// 上次落库的版本三元组：跳过无变化的 UPDATE（不随每次上报写库）。
    runtime_persisted: StdMutex<HashMap<String, crate::challenge::NodeRuntime>>,
    /// 内存中的 Node 协议版本（Hello 携带、挑战被认证 rpc 取走时记录）。
    protocol_versions: StdMutex<HashMap<String, u32>>,
}

impl HealthCenter {
    pub fn new() -> Self {
        Self::default()
    }

    /// 收到一份 Health Report（同时刷新 last_seen）。
    pub fn note_report(&self, node_id: &str, report: NodeHealth) {
        self.note_report_at(node_id, report, Instant::now());
    }

    /// 指定收到时刻的版本（测试注入过期报告用）。
    pub(crate) fn note_report_at(&self, node_id: &str, report: NodeHealth, at: Instant) {
        let mut reports = self.reports.lock().expect("health reports poisoned");
        reports.insert(node_id.to_string(), ReceivedReport { report, at });
        drop(reports);
        self.note_seen(node_id);
    }

    /// 观测到该 Node 一次（内存实时更新，不写库）。
    pub fn note_seen(&self, node_id: &str) {
        let now = unix_now();
        let mut last_seen = self.last_seen.lock().expect("last seen poisoned");
        last_seen.insert(node_id.to_string(), now);
        drop(last_seen);
        let mut dirty = self
            .dirty_last_seen
            .lock()
            .expect("last seen dirty poisoned");
        dirty.insert(node_id.to_string(), now);
    }

    /// 该 Node 的 last_seen；从未观测到为 None。
    pub fn last_seen(&self, node_id: &str) -> Option<i64> {
        self.last_seen
            .lock()
            .expect("last seen poisoned")
            .get(node_id)
            .copied()
    }

    /// 记录 Node 的协议版本（用于「已到协议支持下限」判定）。
    pub fn note_protocol(&self, node_id: &str, protocol_version: u32) {
        self.protocol_versions
            .lock()
            .expect("protocol versions poisoned")
            .insert(node_id.to_string(), protocol_version);
    }

    pub fn protocol_version(&self, node_id: &str) -> Option<u32> {
        self.protocol_versions
            .lock()
            .expect("protocol versions poisoned")
            .get(node_id)
            .copied()
    }

    /// 版本三元组是否有变化（有变化才落库并更新缓存）。
    pub fn remember_runtime(&self, node_id: &str, runtime: &crate::challenge::NodeRuntime) -> bool {
        let mut persisted = self
            .runtime_persisted
            .lock()
            .expect("runtime cache poisoned");
        if persisted.get(node_id) == Some(runtime) {
            return false;
        }
        persisted.insert(node_id.to_string(), runtime.clone());
        true
    }

    /// 未过期的 Health Report；没有或已过期返回 None。
    pub fn fresh_report(&self, node_id: &str) -> Option<ReceivedReport> {
        self.reports
            .lock()
            .expect("health reports poisoned")
            .get(node_id)
            .filter(|received| received.at.elapsed() <= REPORT_TTL)
            .cloned()
    }

    /// 全部未过期的 Health Report 快照（指标与圆点共用）。
    pub fn fresh_reports(&self) -> HashMap<String, NodeHealth> {
        self.reports
            .lock()
            .expect("health reports poisoned")
            .iter()
            .filter(|(_, received)| received.at.elapsed() <= REPORT_TTL)
            .map(|(node_id, received)| (node_id.clone(), received.report.clone()))
            .collect()
    }

    /// 是否收到过 Health Report（含已过期的）。
    pub fn has_report(&self, node_id: &str) -> bool {
        self.reports
            .lock()
            .expect("health reports poisoned")
            .contains_key(node_id)
    }

    /// 取走待落库的 last_seen：`keep` 为 false 的条目（离线 Node）立即返回，
    /// 为 true 的保留到下一轮（5 分钟批量）。返回 (node_id, unix) 列表。
    pub fn drain_last_seen(
        &self,
        keep_online: bool,
        is_online: &dyn Fn(&str) -> bool,
    ) -> Vec<(String, i64)> {
        let mut dirty = self
            .dirty_last_seen
            .lock()
            .expect("last seen dirty poisoned");
        let mut out = Vec::new();
        let mut retain = HashMap::new();
        for (node_id, unix) in dirty.iter() {
            let online = is_online(node_id);
            if online == keep_online {
                out.push((node_id.clone(), *unix));
            } else {
                retain.insert(node_id.clone(), *unix);
            }
        }
        *dirty = retain;
        out
    }
}

/// 版本比较结论（规格 §6 版本表）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionStatus {
    /// 与 coord 语义化版本相同（commit 可能不同，界面只显示 commit）。
    Same,
    /// 低于 coord：黄。
    Behind,
    /// 低于 coord 且协议版本已到 MIN_SUPPORTED_PROTOCOL_VERSION（再落后就会
    /// 被拒）：红。协议版本不落后（与 coord 同代）的低版本不算。
    AtMin,
    /// 高于 coord：蓝（升级顺序反了，非异常）。
    Ahead,
    /// 未上报（旧 Node，< 0.3）或版本串无法解析。
    Unknown,
}

impl VersionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            VersionStatus::Same => "same",
            VersionStatus::Behind => "behind",
            VersionStatus::AtMin => "at_min",
            VersionStatus::Ahead => "ahead",
            VersionStatus::Unknown => "unknown",
        }
    }
}

/// 版本比较（OB-5）：只比语义化版本、忽略 commit；基准是 coord 自身版本。
/// node_protocol 是内存里该 Node 的协议版本（None = coord 重启后未再上报）。
pub fn version_status(
    node_version: Option<&str>,
    coord_semver: &str,
    node_protocol: Option<u32>,
    min_supported_protocol: u32,
) -> VersionStatus {
    let Some(text) = node_version else {
        return VersionStatus::Unknown;
    };
    let Some(node_semver) = semver_of(text) else {
        return VersionStatus::Unknown;
    };
    let Some(coord) = semver_of(coord_semver) else {
        return VersionStatus::Unknown;
    };
    if node_semver == coord {
        return VersionStatus::Same;
    }
    if node_semver > coord {
        return VersionStatus::Ahead;
    }
    // 落后：协议版本也已到支持下限时升格为红（再落后就会被拒）。
    if node_protocol == Some(min_supported_protocol) {
        VersionStatus::AtMin
    } else {
        VersionStatus::Behind
    }
}

/// 版本串里的语义化版本部分（`0.3.0 (a1b2c3d)` → `0.3.0`）；无空格分隔时
/// 原样返回。指标标签也用它（不含 commit，序列数不随构建数增长）。
pub fn semver_head(text: &str) -> &str {
    text.split_whitespace().next().unwrap_or(text)
}

fn semver_of(text: &str) -> Option<(u64, u64, u64)> {
    let head = semver_head(text);
    let mut parts = head.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

/// 健康圆点颜色（规格 §6 健康圆点表，红 → 黄 → 蓝 → 绿，灰为缺数据）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotColor {
    Red,
    Yellow,
    Blue,
    Green,
    Gray,
}

impl DotColor {
    pub fn as_str(self) -> &'static str {
        match self {
            DotColor::Red => "red",
            DotColor::Yellow => "yellow",
            DotColor::Blue => "blue",
            DotColor::Green => "green",
            DotColor::Gray => "gray",
        }
    }
}

/// 健康圆点判定的输入。
pub struct DotInput<'a> {
    /// Network Map 下发流是否打开。
    pub online: bool,
    /// Health Report 与其年龄（秒）；None = 从未收到。
    pub report: Option<(&'a NodeHealth, u64)>,
    /// 版本比较结论（与圆点同一张表）。
    pub version_status: VersionStatus,
}

/// 健康圆点判定（纯函数）：自上而下取第一条命中，返回颜色与命中的条件
/// （中文，悬停展示）。只有 `punch_pending` 不标黄（它不在任何条件里）。
pub fn health_dot(input: &DotInput) -> (DotColor, Vec<String>) {
    // 灰：离线 / 从未收到 / 已过期（没有可判定的数据）。
    if !input.online {
        return (DotColor::Gray, vec!["离线".to_string()]);
    }
    let Some((report, age_secs)) = input.report else {
        return (
            DotColor::Gray,
            vec!["等待上报（hzd < 0.3 或刚启动）".to_string()],
        );
    };
    if age_secs > REPORT_TTL.as_secs() {
        return (DotColor::Gray, vec!["Health Report 已过期".to_string()]);
    }

    let mut reasons = Vec::new();
    // 红。
    if !report.udp4_ok && !report.udp6_ok {
        reasons.push("IPv4 与 IPv6 UDP 均不可用".to_string());
    }
    if report.suspicious_endpoint {
        reasons.push("上报了可疑 Endpoint（198.18.0.0/15 或回环）".to_string());
    }
    if input.version_status == VersionStatus::AtMin {
        reasons.push("协议版本已到支持下限，再落后将被拒绝".to_string());
    }
    if !reasons.is_empty() {
        return (DotColor::Red, reasons);
    }

    // 黄。
    if input.version_status == VersionStatus::Behind {
        reasons.push("版本落后于服务端".to_string());
    }
    if !report.has_stun_mapping {
        reasons.push("无公网 STUN 映射".to_string());
    }
    for (_, reason) in &report.relayed_peers {
        match reason.as_str() {
            hz_core::health::REASON_NO_CANDIDATES => {
                reasons.push("有对端无可用候选（no_candidates）".to_string())
            }
            hz_core::health::REASON_HANDSHAKE_TIMEOUT => {
                reasons.push("有对端握手超时（handshake_timeout）".to_string())
            }
            _ => {}
        }
    }
    if report.default_route_virtual {
        reasons.push("默认路由由虚拟网卡持有".to_string());
    }
    if report.nat == "hard" {
        reasons.push("NAT 为端点相关映射（hard），与 hard NAT 对端无法直连".to_string());
    }
    if !reasons.is_empty() {
        return (DotColor::Yellow, reasons);
    }

    // 蓝：高于服务端（升级顺序反了，非异常）。
    if input.version_status == VersionStatus::Ahead {
        return (DotColor::Blue, vec!["版本高于服务端".to_string()]);
    }
    (DotColor::Green, Vec::new())
}

/// last_seen 批量落库循环：离线 Node 的脏条目每 5 秒冲一次（流断开即落库），
/// 在线 Node 的每 5 分钟冲一次（不随每次上报写库）。is_online 来自 MapHub。
pub async fn run_last_seen_flush(
    store: crate::store::Store,
    hub: Arc<crate::map_stream::MapHub>,
    health: Arc<HealthCenter>,
) {
    let mut offline_tick = tokio::time::interval(OFFLINE_FLUSH_EVERY);
    let mut online_tick = tokio::time::interval(ONLINE_FLUSH_EVERY);
    loop {
        tokio::select! {
            _ = offline_tick.tick() => {
                let entries = health.drain_last_seen(false, &|node_id| hub.is_online(node_id));
                flush(&store, entries).await;
            }
            _ = online_tick.tick() => {
                let entries = health.drain_last_seen(true, &|node_id| hub.is_online(node_id));
                flush(&store, entries).await;
            }
        }
    }
}

async fn flush(store: &crate::store::Store, entries: Vec<(String, i64)>) {
    if entries.is_empty() {
        return;
    }
    if let Err(error) = store.flush_last_seen(&entries).await {
        tracing::warn!(%error, count = entries.len(), "flush last_seen failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health(nat: &str) -> NodeHealth {
        NodeHealth {
            udp4_ok: true,
            udp6_ok: false,
            has_stun_mapping: true,
            nat: nat.to_string(),
            default_route_virtual: false,
            suspicious_endpoint: false,
            direct_peers: 1,
            relayed_peers: vec![],
        }
    }

    fn dot(
        online: bool,
        report: Option<(&NodeHealth, u64)>,
        status: VersionStatus,
    ) -> (DotColor, Vec<String>) {
        health_dot(&DotInput {
            online,
            report,
            version_status: status,
        })
    }

    /// 规格 §6 健康圆点表逐行 + punch_pending 不标黄 + 过期为灰。
    #[test]
    fn health_dot_table() {
        let base = health("unknown");

        // 灰：离线 / 从未收到 / 过期。
        assert_eq!(
            dot(false, Some((&base, 0)), VersionStatus::Same).0,
            DotColor::Gray
        );
        assert_eq!(dot(true, None, VersionStatus::Same).0, DotColor::Gray);
        assert_eq!(
            dot(
                true,
                Some((&base, REPORT_TTL.as_secs() + 1)),
                VersionStatus::Same
            )
            .0,
            DotColor::Gray
        );

        // 红：双栈 UDP 全断。
        let mut broken = health("unknown");
        broken.udp4_ok = false;
        broken.udp6_ok = false;
        let (color, reasons) = dot(true, Some((&broken, 0)), VersionStatus::Same);
        assert_eq!(color, DotColor::Red);
        assert!(reasons.iter().any(|r| r.contains("UDP")));

        // 红：可疑 Endpoint。
        let mut suspicious = health("unknown");
        suspicious.suspicious_endpoint = true;
        assert_eq!(
            dot(true, Some((&suspicious, 0)), VersionStatus::Same).0,
            DotColor::Red
        );

        // 红：协议版本到支持下限。
        assert_eq!(
            dot(true, Some((&base, 0)), VersionStatus::AtMin).0,
            DotColor::Red
        );

        // 黄：版本落后。
        assert_eq!(
            dot(true, Some((&base, 0)), VersionStatus::Behind).0,
            DotColor::Yellow
        );
        // 黄：无 STUN 映射。
        let mut no_mapping = health("unknown");
        no_mapping.has_stun_mapping = false;
        assert_eq!(
            dot(true, Some((&no_mapping, 0)), VersionStatus::Same).0,
            DotColor::Yellow
        );
        // 黄：no_candidates / handshake_timeout 的 Relayed 对端。
        let mut relayed = health("unknown");
        relayed.relayed_peers = vec![("n-2".into(), "no_candidates".into())];
        let (color, reasons) = dot(true, Some((&relayed, 0)), VersionStatus::Same);
        assert_eq!(color, DotColor::Yellow);
        assert!(reasons.iter().any(|r| r.contains("no_candidates")));
        // 黄：默认路由虚拟网卡 / nat=hard（提示性）。
        let mut virtual_route = health("unknown");
        virtual_route.default_route_virtual = true;
        assert_eq!(
            dot(true, Some((&virtual_route, 0)), VersionStatus::Same).0,
            DotColor::Yellow
        );
        let hard = health("hard");
        assert_eq!(
            dot(true, Some((&hard, 0)), VersionStatus::Same).0,
            DotColor::Yellow
        );

        // 蓝：高于服务端。
        assert_eq!(
            dot(true, Some((&base, 0)), VersionStatus::Ahead).0,
            DotColor::Blue
        );

        // 绿：以上皆否。
        assert_eq!(
            dot(true, Some((&base, 0)), VersionStatus::Same).0,
            DotColor::Green
        );

        // punch_pending 不标黄。
        let mut pending = health("unknown");
        pending.relayed_peers = vec![("n-3".into(), "punch_pending".into())];
        let (color, _) = dot(true, Some((&pending, 0)), VersionStatus::Same);
        assert_eq!(color, DotColor::Green, "punch_pending 不计入黄色条件");
    }

    #[test]
    fn version_status_compares_semver_only() {
        let coord = "0.3.0";
        // 低于 / 等于 / 高于（忽略 commit）。
        assert_eq!(
            version_status(Some("0.2.2 (abcdef1)"), coord, Some(99), 1),
            VersionStatus::Behind
        );
        assert_eq!(
            version_status(Some("0.3.0 (a1b2c3d)"), coord, Some(1), 1),
            VersionStatus::Same,
            "同版本不同 commit 只算 same"
        );
        assert_eq!(
            version_status(Some("0.3.1"), coord, Some(1), 1),
            VersionStatus::Ahead
        );
        assert_eq!(
            version_status(Some("1.0.0"), coord, Some(1), 1),
            VersionStatus::Ahead
        );
        // 旧 Node 未上报。
        assert_eq!(version_status(None, coord, None, 1), VersionStatus::Unknown);
        assert_eq!(
            version_status(Some("garbage"), coord, None, 1),
            VersionStatus::Unknown
        );
    }

    #[test]
    fn version_status_flags_nodes_at_the_protocol_floor() {
        // 落后且协议版本已到下限 → 红（再落后就会被拒）。
        assert_eq!(
            version_status(Some("0.2.2"), "0.3.0", Some(1), 1),
            VersionStatus::AtMin
        );
        // 落后但协议版本未到下限（coord 已升代）→ 黄。
        assert_eq!(
            version_status(Some("0.3.2"), "0.4.0", Some(3), 2),
            VersionStatus::Behind
        );
        // 协议版本未知（coord 重启后未再 Hello）→ 按黄处理。
        assert_eq!(
            version_status(Some("0.2.2"), "0.3.0", None, 1),
            VersionStatus::Behind
        );
    }

    #[test]
    fn reports_expire_after_ttl_and_last_seen_flushes() {
        let center = HealthCenter::new();
        center.note_report("n1", health("easy"));
        assert!(center.fresh_report("n1").is_some());
        // 直接注入一份已过期的报告：90 秒未更新即过期。
        center.note_report_at(
            "n2",
            health("easy"),
            Instant::now() - REPORT_TTL - Duration::from_secs(1),
        );
        assert!(center.fresh_report("n2").is_none(), "90 秒未更新视为过期");
        assert!(
            center.has_report("n2"),
            "过期的报告仍在内存（has_report 区分从未收到）"
        );
        assert!(!center.fresh_reports().contains_key("n2"));
        assert!(center.fresh_reports().contains_key("n1"));

        // last_seen：在线条目等 5 分钟批量，离线条目立即冲（n1 在线，n2 与
        // offline 离线）。
        let hub = crate::map_stream::MapHub::new();
        let _rx_online = hub.register("n1".into());
        center.note_seen("offline");
        let drained = center.drain_last_seen(false, &|id| hub.is_online(id));
        let mut drained_ids: Vec<&str> = drained.iter().map(|(id, _)| id.as_str()).collect();
        drained_ids.sort_unstable();
        assert_eq!(drained_ids, vec!["n2", "offline"], "只有离线条目立即落库");
        let again = center.drain_last_seen(false, &|id| hub.is_online(id));
        assert!(again.is_empty(), "冲掉后不再重复落库");
        let batch = center.drain_last_seen(true, &|id| hub.is_online(id));
        let batch_ids: Vec<&str> = batch.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(batch_ids, vec!["n1"], "在线条目等 5 分钟批量");
    }

    #[test]
    fn runtime_cache_flags_changes() {
        let center = HealthCenter::new();
        let runtime = crate::challenge::NodeRuntime {
            node_version: Some("0.3.0".into()),
            os: Some("macos".into()),
            arch: Some("aarch64".into()),
        };
        assert!(center.remember_runtime("n1", &runtime), "首次必然落库");
        assert!(!center.remember_runtime("n1", &runtime), "无变化不写库");
        let upgraded = crate::challenge::NodeRuntime {
            node_version: Some("0.3.1".into()),
            ..runtime
        };
        assert!(center.remember_runtime("n1", &upgraded));
    }
}
