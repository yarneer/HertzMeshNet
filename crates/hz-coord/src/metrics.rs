//! Coordination Server 的 Prometheus 指标（FR-12）：独立明文 HTTP 监听。
//!
//! 指标：
//! - `hz_coord_online_nodes`：打开中的 Network Map 下发流数（抓取时从 MapHub 读）。
//! - `hz_coord_punch_attempts_total` / `hz_coord_punch_success_total`：Node 经
//!   ReportEndpoints 上报的累计打洞计数按 Node 求差量后累加的全局计数。
//! - `hz_coord_punch_success_ratio`：服务端算好的成功率（= success / attempts），
//!   PromQL 里也可以直接用两个 counter 自己除。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};

use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use prometheus::{Encoder, Gauge, IntCounter, IntGauge, Registry, TextEncoder};

use crate::map_stream::MapHub;

pub struct Metrics {
    registry: Registry,
    online: IntGauge,
    punch_attempts: IntCounter,
    punch_success: IntCounter,
    punch_ratio: Gauge,
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
        registry.register(Box::new(online.clone()))?;
        registry.register(Box::new(punch_attempts.clone()))?;
        registry.register(Box::new(punch_success.clone()))?;
        registry.register(Box::new(punch_ratio.clone()))?;
        Ok(Self {
            registry,
            online,
            punch_attempts,
            punch_success,
            punch_ratio,
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
}

async fn scrape(State(state): State<Arc<MetricsState>>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        state.metrics.encode_refreshing_online(&state.hub),
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
) -> anyhow::Result<MetricsHandle> {
    let state = Arc::new(MetricsState { hub, metrics });
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
}
