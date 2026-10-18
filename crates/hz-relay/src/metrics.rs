//! Relay 的 Prometheus 指标（FR-12）：独立于 gRPC/TLS 面的明文 HTTP 监听，
//! 供 Prometheus 抓取。每个 serve_relay 实例持有私有 Registry，
//! 同进程多实例（测试）互不冲突。
//!
//! 指标：
//! - `hz_relay_node_bytes_total{node_id,direction}`：direction=in 为该 Node
//!   发往 Relay 并被放行的字节数，direction=out 为 Relay 投递给该 Node 的字节数。
//! - `hz_relay_dropped_bytes_total{node_id}`：因超出发送方限速被丢弃的字节数。
//! - `hz_relay_sessions`：当前打开的 Relay 会话数。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use prometheus::{Encoder, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};

pub struct Metrics {
    registry: Registry,
    node_bytes: IntCounterVec,
    dropped_bytes: IntCounterVec,
    sessions: IntGauge,
}

impl Metrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();
        let node_bytes = IntCounterVec::new(
            Opts::new(
                "hz_relay_node_bytes_total",
                "Relayed bytes admitted from (in) / delivered to (out) each node.",
            ),
            &["node_id", "direction"],
        )?;
        let dropped_bytes = IntCounterVec::new(
            Opts::new(
                "hz_relay_dropped_bytes_total",
                "Bytes dropped because the sending node exceeded its relay rate limit.",
            ),
            &["node_id"],
        )?;
        let sessions = IntGauge::new(
            "hz_relay_sessions",
            "Currently open relay sessions (one per connected node).",
        )?;
        registry.register(Box::new(node_bytes.clone()))?;
        registry.register(Box::new(dropped_bytes.clone()))?;
        registry.register(Box::new(sessions.clone()))?;
        Ok(Self {
            registry,
            node_bytes,
            dropped_bytes,
            sessions,
        })
    }

    /// 一个帧成功从 src 转发到 dst：入口记入 src 的 in，投递记入 dst 的 out。
    pub fn note_forward(&self, src: &str, dst: &str, len: usize) {
        self.node_bytes
            .with_label_values(&[src, "in"])
            .inc_by(len as u64);
        self.node_bytes
            .with_label_values(&[dst, "out"])
            .inc_by(len as u64);
    }

    pub fn note_drop(&self, node_id: &str, len: usize) {
        self.dropped_bytes
            .with_label_values(&[node_id])
            .inc_by(len as u64);
    }

    pub fn session_opened(&self) {
        self.sessions.inc();
    }

    pub fn session_closed(&self) {
        self.sessions.dec();
    }

    pub fn encode(&self) -> String {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let _ = encoder.encode(&self.registry.gather(), &mut buffer);
        String::from_utf8_lossy(&buffer).into_owned()
    }
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

async fn scrape(State(metrics): State<Arc<Metrics>>) -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        metrics.encode(),
    )
}

pub async fn serve_metrics(
    listen: SocketAddr,
    metrics: Arc<Metrics>,
) -> anyhow::Result<MetricsHandle> {
    let app = Router::new()
        .route("/metrics", get(scrape))
        .with_state(metrics);
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
            tracing::error!(%error, "relay metrics server exited with error");
        }
    });
    tracing::info!(%local_addr, "relay metrics server listening");
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
    fn counters_render_prometheus_text_with_labels() {
        let metrics = Metrics::new().unwrap();
        metrics.note_forward("n1", "n2", 100);
        metrics.note_drop("n1", 40);
        metrics.session_opened();
        let text = metrics.encode();
        assert!(
            text.contains("hz_relay_node_bytes_total{direction=\"in\",node_id=\"n1\"} 100"),
            "实际输出：\n{text}"
        );
        assert!(
            text.contains("hz_relay_node_bytes_total{direction=\"out\",node_id=\"n2\"} 100"),
            "实际输出：\n{text}"
        );
        assert!(
            text.contains("hz_relay_dropped_bytes_total{node_id=\"n1\"} 40"),
            "实际输出：\n{text}"
        );
        assert!(text.contains("hz_relay_sessions 1"), "实际输出：\n{text}");
    }
}
