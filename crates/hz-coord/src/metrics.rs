//! Coordination Server 的 Prometheus 指标（FR-12）：独立明文 HTTP 监听。
//!
//! 指标：
//! - `hz_coord_online_nodes`：打开中的 Network Map 下发流数（抓取时从 MapHub 读）。
//! - `hz_coord_punch_attempts_total` / `hz_coord_punch_success_total`：Node 经
//!   ReportEndpoints 上报的累计打洞计数按 Node 求差量后累加的全局计数。
//! - `hz_coord_punch_success_ratio`：服务端算好的成功率（= success / attempts），
//!   PromQL 里也可以直接用两个 counter 自己除。
//! - `hz_coord_nodes`（#74，gauge，标签 `version`、`os`）：在线且 Health Report
//!   未过期的 Node 数按版本/平台分组。
//! - `hz_coord_relayed_paths`（gauge，标签 `reason`）：未过期报告里 Relayed
//!   对端数按原因分组。
//! - `hz_coord_nodes_unhealthy`（gauge，标签 `check`）：`udp4`、`stun_mapping`、
//!   `suspicious_endpoint` 三项检查未通过的 Node 数。
//!
//! 可观测性 gauge 的标签不含 node_id，序列数不随 Node 数增长。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};

use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use prometheus::{Encoder, Gauge, GaugeVec, IntCounter, IntGauge, Opts, Registry, TextEncoder};

use crate::health::HealthCenter;
use crate::map_stream::MapHub;
use crate::store::{ListedNode, NodeScope, Store};

pub struct Metrics {
    registry: Registry,
    online: IntGauge,
    punch_attempts: IntCounter,
    punch_success: IntCounter,
    punch_ratio: Gauge,
    nodes_by_version: GaugeVec,
    relayed_by_reason: GaugeVec,
    unhealthy_by_check: GaugeVec,
    /// 上次抓取各 gauge 的标签组合（\x1 连接）：值变化或消失时删掉旧序列，
    /// 避免序列残留（prometheus 0.13 的 MetricVec 没有整体 reset）。
    nodes_labels: StdMutex<std::collections::HashSet<String>>,
    relayed_labels: StdMutex<std::collections::HashSet<String>>,
    unhealthy_labels: StdMutex<std::collections::HashSet<String>>,
    /// 每个 Node 最近一次上报的累计值；差量进全局计数，重启（归零）只记基线。
    last_report: StdMutex<HashMap<String, (u64, u64)>>,
}

impl Metrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();
        let online = IntGauge::new(
            "hz_coord_online_nodes",
            "Nodes with an open network map stream.",
        )?;
        let punch_attempts = IntCounter::new(
            "hz_coord_punch_attempts_total",
            "Punch attempts reported by nodes (cumulative deltas).",
        )?;
        let punch_success = IntCounter::new(
            "hz_coord_punch_success_total",
            "Punch successes (relay-to-direct upgrades) reported by nodes.",
        )?;
        let punch_ratio = Gauge::new(
            "hz_coord_punch_success_ratio",
            "Server-side punch success ratio (success / attempts).",
        )?;
        let nodes_by_version = GaugeVec::new(
            Opts::new(
                "hz_coord_nodes",
                "Online nodes with a fresh health report, by version and os.",
            ),
            &["version", "os"],
        )?;
        let relayed_by_reason = GaugeVec::new(
            Opts::new(
                "hz_coord_relayed_paths",
                "Relayed peer paths from fresh health reports, by reason.",
            ),
            &["reason"],
        )?;
        let unhealthy_by_check = GaugeVec::new(
            Opts::new(
                "hz_coord_nodes_unhealthy",
                "Online nodes failing a health check (fresh reports only).",
            ),
            &["check"],
        )?;
        registry.register(Box::new(online.clone()))?;
        registry.register(Box::new(punch_attempts.clone()))?;
        registry.register(Box::new(punch_success.clone()))?;
        registry.register(Box::new(punch_ratio.clone()))?;
        registry.register(Box::new(nodes_by_version.clone()))?;
        registry.register(Box::new(relayed_by_reason.clone()))?;
        registry.register(Box::new(unhealthy_by_check.clone()))?;
        Ok(Self {
            registry,
            online,
            punch_attempts,
            punch_success,
            punch_ratio,
            nodes_by_version,
            relayed_by_reason,
            unhealthy_by_check,
            nodes_labels: StdMutex::new(std::collections::HashSet::new()),
            relayed_labels: StdMutex::new(std::collections::HashSet::new()),
            unhealthy_labels: StdMutex::new(std::collections::HashSet::new()),
            last_report: StdMutex::new(HashMap::new()),
        })
    }

    /// 记一份 Node 上报的累计打洞计数：与该 Node 上次值求差量加进全局计数；
    /// 计数回退（Node 重启）时只刷新基线，不加负数。
    pub fn note_path_report(&self, node_id: &str, attempts: u64, success: u64) {
        let mut last = self.last_report.lock().expect("path report poisoned");
        match last.get(node_id) {
            Some(&(prev_attempts, prev_success))
                if attempts >= prev_attempts && success >= prev_success =>
            {
                self.punch_attempts.inc_by(attempts - prev_attempts);
                self.punch_success.inc_by(success - prev_success);
            }
            _ => {}
        }
        last.insert(node_id.to_owned(), (attempts, success));
        self.refresh_ratio();
    }

    /// 打洞计数摘要（Relay 路径指标）。与 Prometheus 计数同一份状态。
    pub fn punch_summary(&self) -> PunchSummary {
        let attempts = self.punch_attempts.get();
        let success = self.punch_success.get();
        PunchSummary {
            attempts,
            success,
            ratio: if attempts == 0 {
                0.0
            } else {
                success as f64 / attempts as f64
            },
        }
    }

    fn refresh_ratio(&self) {
        let attempts = self.punch_attempts.get();
        let success = self.punch_success.get();
        let ratio = if attempts == 0 {
            0.0
        } else {
            success as f64 / attempts as f64
        };
        self.punch_ratio.set(ratio);
    }

    /// 抓取时刷新在线数并导出文本。
    pub fn encode_refreshing_online(&self, hub: &MapHub) -> String {
        self.online.set(hub.online_nodes() as i64);
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let _ = encoder.encode(&self.registry.gather(), &mut buffer);
        String::from_utf8_lossy(&buffer).into_owned()
    }

    /// 抓取时刷新全部 gauge（#74）：三个可观测性 gauge 只统计在线且
    /// Health Report 未过期的 Node；标签取版本串的 semver 部分（不含
    /// commit，序列数不随构建数增长）与平台，未上报记 `unknown`。
    pub fn encode_observability(
        &self,
        hub: &MapHub,
        health: &HealthCenter,
        nodes: &[ListedNode],
    ) -> String {
        self.online.set(hub.online_nodes() as i64);

        let reports = health.fresh_reports();
        let mut version_counts: HashMap<(String, String), f64> = HashMap::new();
        let mut reason_counts: HashMap<String, f64> = HashMap::new();
        let mut check_counts: HashMap<&str, f64> = HashMap::new();
        for node in nodes {
            if !hub.is_online(&node.node_id) {
                continue;
            }
            let Some(report) = reports.get(&node.node_id) else {
                continue;
            };
            let version = node
                .node_version
                .as_deref()
                .filter(|text| !text.trim().is_empty())
                .map(crate::health::semver_head)
                .unwrap_or("unknown");
            let os = node.os.as_deref().unwrap_or("unknown");
            *version_counts
                .entry((version.to_string(), os.to_string()))
                .or_insert(0.0) += 1.0;
            for (_, reason) in &report.relayed_peers {
                *reason_counts.entry(reason.clone()).or_insert(0.0) += 1.0;
            }
            if !report.udp4_ok {
                *check_counts.entry("udp4").or_insert(0.0) += 1.0;
            }
            if !report.has_stun_mapping {
                *check_counts.entry("stun_mapping").or_insert(0.0) += 1.0;
            }
            if report.suspicious_endpoint {
                *check_counts.entry("suspicious_endpoint").or_insert(0.0) += 1.0;
            }
        }
        let version_series: Vec<(Vec<String>, f64)> = version_counts
            .into_iter()
            .map(|((version, os), count)| (vec![version, os], count))
            .collect();
        let reason_series: Vec<(Vec<String>, f64)> = reason_counts
            .into_iter()
            .map(|(reason, count)| (vec![reason], count))
            .collect();
        let check_series: Vec<(Vec<String>, f64)> = check_counts
            .into_iter()
            .map(|(check, count)| (vec![check.to_string()], count))
            .collect();
        replace_series(&self.nodes_by_version, &self.nodes_labels, &version_series);
        replace_series(
            &self.relayed_by_reason,
            &self.relayed_labels,
            &reason_series,
        );
        replace_series(
            &self.unhealthy_by_check,
            &self.unhealthy_labels,
            &check_series,
        );

        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let _ = encoder.encode(&self.registry.gather(), &mut buffer);
        String::from_utf8_lossy(&buffer).into_owned()
    }
}

/// 把一个 GaugeVec 的序列整体替换为本次的标签组合：消失的组合删序列，
/// 新组合设值。键用 \x1 连接（标签值里不会出现）。
fn replace_series(
    gauge: &GaugeVec,
    seen: &StdMutex<std::collections::HashSet<String>>,
    series: &[(Vec<String>, f64)],
) {
    let mut seen = seen.lock().expect("gauge labels poisoned");
    let fresh: std::collections::HashSet<String> = series
        .iter()
        .map(|(labels, _)| labels.join("\u{1}"))
        .collect();
    for stale in seen.difference(&fresh) {
        let labels: Vec<&str> = stale.split('\u{1}').collect();
        if gauge.remove_label_values(&labels).is_err() {
            tracing::warn!(?labels, "remove stale metric series failed");
        }
    }
    for (labels, value) in series {
        let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        gauge.with_label_values(&refs).set(*value);
    }
    *seen = fresh;
}

/// `hz_coord_punch_*` 的当前值，给 Admin 健康页，不走 Prometheus 文本。
#[derive(Debug, Clone, Copy)]
pub struct PunchSummary {
    pub attempts: u64,
    pub success: u64,
    pub ratio: f64,
}

struct MetricsState {
    hub: Arc<MapHub>,
    metrics: Arc<Metrics>,
    health: Arc<HealthCenter>,
    store: Store,
}

async fn scrape(State(state): State<Arc<MetricsState>>) -> impl IntoResponse {
    let nodes = match state.store.list_nodes(&NodeScope::All).await {
        Ok(nodes) => nodes,
        Err(error) => {
            tracing::error!(%error, "metrics scrape: list nodes failed");
            Vec::new()
        }
    };
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        state
            .metrics
            .encode_observability(&state.hub, &state.health, &nodes),
    )
}

pub struct MetricsHandle {
    pub local_addr: SocketAddr,
    shutdown: tokio::sync::watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

impl MetricsHandle {
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub async fn terminated(self) {
        let _ = self.join.await;
    }
}

pub async fn serve_metrics(
    listen: SocketAddr,
    hub: Arc<MapHub>,
    metrics: Arc<Metrics>,
    health: Arc<HealthCenter>,
    store: Store,
) -> anyhow::Result<MetricsHandle> {
    let state = Arc::new(MetricsState {
        hub,
        metrics,
        health,
        store,
    });
    let app = Router::new()
        .route("/metrics", get(scrape))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let local_addr = listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let join = tokio::spawn(async move {
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await;
        if let Err(error) = result {
            tracing::error!(%error, "coord metrics server exited with error");
        }
    });
    tracing::info!(%local_addr, "coord metrics server listening");
    Ok(MetricsHandle {
        local_addr,
        shutdown: shutdown_tx,
        join,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_reports_accumulate_as_per_node_deltas() {
        let metrics = Metrics::new().unwrap();
        metrics.note_path_report("n1", 10, 4); // 基线
        metrics.note_path_report("n2", 5, 5); // 基线
        metrics.note_path_report("n1", 13, 6); // 差量 +3/+2
        // 重启归零：只刷新基线，不加负数。
        metrics.note_path_report("n1", 1, 1);
        metrics.note_path_report("n1", 3, 2); // 差量 +2/+1

        let text = metrics.encode_refreshing_online(&MapHub::new());
        assert!(
            text.contains("hz_coord_punch_attempts_total 5"),
            "只有差量进全局计数（3+2），实际：\n{text}"
        );
        assert!(
            text.contains("hz_coord_punch_success_total 3"),
            "n1 差量 2+1，实际：\n{text}"
        );
        assert!(
            text.contains("hz_coord_punch_success_ratio 0.6"),
            "3/5 的比率应原样可读，实际：\n{text}"
        );
        assert!(text.contains("hz_coord_online_nodes 0"));
    }

    #[test]
    fn online_nodes_counts_open_map_streams() {
        let hub = MapHub::new();
        let metrics = Metrics::new().unwrap();
        let _rx_a = hub.register("a".into());
        let _rx_b = hub.register("b".into());
        let text = metrics.encode_refreshing_online(&hub);
        assert!(text.contains("hz_coord_online_nodes 2"), "实际：\n{text}");
        let _rx_a2 = hub.register("a".into()); // 同 Node 重开替换旧流，不增数
        let text = metrics.encode_refreshing_online(&hub);
        assert!(text.contains("hz_coord_online_nodes 2"), "实际：\n{text}");
    }

    fn listed(id: &str, version: Option<&str>, os: Option<&str>) -> ListedNode {
        ListedNode {
            node_id: id.to_string(),
            name: format!("node-{id}"),
            ipv4: "100.96.0.1".to_string(),
            ipv6: "fd00::1".to_string(),
            tags: vec![],
            owner_user: None,
            expires_at_unix: None,
            revoked: false,
            revoked_at_unix: None,
            created_at_unix: 0,
            node_version: version.map(str::to_string),
            os: os.map(str::to_string),
            arch: None,
            last_seen_unix: None,
        }
    }

    fn report(nat: &str, relayed: &[(&str, &str)]) -> crate::health::NodeHealth {
        crate::health::NodeHealth {
            udp4_ok: true,
            udp6_ok: false,
            has_stun_mapping: true,
            nat: nat.to_string(),
            default_route_virtual: false,
            suspicious_endpoint: false,
            direct_peers: 0,
            relayed_peers: relayed
                .iter()
                .map(|(id, reason)| (id.to_string(), reason.to_string()))
                .collect(),
        }
    }

    /// Seam B（#74 验收）：构造若干 Node 的 Health Report，三个指标取值正确；
    /// 过期与离线的不计入；标签集中不出现 node_id。
    #[test]
    fn observability_gauges_count_fresh_online_reports_only() {
        let hub = MapHub::new();
        let health = HealthCenter::new();
        let metrics = Metrics::new().unwrap();

        // 两个在线且报告新鲜的 Node；第三个在线但报告过期，第四个报告新鲜
        // 但流已断开（从未开流）。
        let _rx_a = hub.register("a".into());
        let _rx_b = hub.register("b".into());
        let _rx_c = hub.register("c".into());
        health.note_report("a", report("unknown", &[("x", "handshake_timeout")]));
        health.note_report("b", report("hard", &[("y", "punch_pending")]));
        health.note_report("c", report("unknown", &[]));
        health.note_report("d", report("unknown", &[("z", "handshake_timeout")]));
        // c 的报告直接过期（注入过去时刻）；d 从未开流。
        health.note_report_at(
            "c",
            report("unknown", &[]),
            std::time::Instant::now() - std::time::Duration::from_secs(120),
        );

        let nodes = vec![
            listed("a", Some("0.3.0 (a1b2c3d)"), Some("macos")),
            listed("b", Some("0.3.0 (a1b2c3d)"), Some("linux")),
            listed("c", Some("0.3.0"), Some("linux")),
            listed("d", None, None),
        ];
        let text = metrics.encode_observability(&hub, &health, &nodes);

        // hz_coord_nodes：a + b 按 (version, os) 分组，各 1；c/d 不计入。
        assert!(
            text.contains("hz_coord_nodes{os=\"macos\",version=\"0.3.0\"} 1"),
            "版本标签取 semver 部分（不带 commit）：\n{text}"
        );
        assert!(
            text.contains("hz_coord_nodes{os=\"linux\",version=\"0.3.0\"} 1"),
            "实际：\n{text}"
        );
        // relayed：handshake_timeout 1（a），punch_pending 1（b）；d 的不计入。
        assert!(
            text.contains("hz_coord_relayed_paths{reason=\"handshake_timeout\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("hz_coord_relayed_paths{reason=\"punch_pending\"} 1"),
            "{text}"
        );
        // unhealthy：三项检查都通过 → 不出现序列。
        assert!(!text.contains("hz_coord_nodes_unhealthy"), "{text}");
        // 标签集不含 node_id / Node Name。
        assert!(
            !text.contains("node-a") && !text.contains("\"a\""),
            "{text}"
        );
    }

    #[test]
    fn unhealthy_gauge_counts_each_check() {
        let hub = MapHub::new();
        let health = HealthCenter::new();
        let metrics = Metrics::new().unwrap();
        let _rx = hub.register("a".into());
        let mut broken = report("unknown", &[]);
        broken.udp4_ok = false;
        broken.has_stun_mapping = false;
        broken.suspicious_endpoint = true;
        health.note_report("a", broken);
        let text = metrics.encode_observability(&hub, &health, &[listed("a", Some("0.3.0"), None)]);
        assert!(
            text.contains("hz_coord_nodes_unhealthy{check=\"udp4\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("hz_coord_nodes_unhealthy{check=\"stun_mapping\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("hz_coord_nodes_unhealthy{check=\"suspicious_endpoint\"} 1"),
            "{text}"
        );
    }
}
