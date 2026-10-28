//! hz-relay（FR-9）：TLS 中继服务。按 node id 寻址转发已加密的 WireGuard
//! 数据报，业务明文对 Relay 不可见。会话登记表（node id → 出向发送端）是
//! 本模块的领域结构；身份校验在流边界完成——首帧 RelayHello 经
//! Coordination Server 的 RelayCheckNode 代理验证，未通过的流不进入转发。

pub mod limiter;
pub mod metrics;
pub mod tls;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use hz_proto::coord_client::CoordClient;
use hz_proto::relay_frame;
use hz_proto::relay_server::{Relay, RelayServer};
use hz_proto::{RelayCheckRequest, RelayData, RelayError, RelayFrame};
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Channel, ServerTlsConfig};
use tonic::{Request, Response, Status, Streaming};

use crate::limiter::Limiter;
use crate::metrics::{Metrics, MetricsHandle, serve_metrics};

/// 认证前等待首帧 RelayHello 的时限。
const HELLO_TIMEOUT: Duration = Duration::from_secs(15);
/// 每会话出向队列深度。满则丢弃该帧（WireGuard 自带重传，不阻塞其他会话）。
const SESSION_DEPTH: usize = 128;
/// 每 Node 的 Relay 限速默认值（FR-9：默认 10 Mbps、可配置）。
pub const DEFAULT_RATE_LIMIT_MBPS: u64 = 10;

/// STUN 的缺省监听端口（#76）：3478 之外再开 3479，两个目标让 Node 比较
/// 映射端口得到 NAT 形态（easy / hard）。未放行 3479 的旧部署只是让
/// `nat=unknown`，不影响其他功能。
pub const DEFAULT_STUN_LISTENS: [&str; 2] = ["0.0.0.0:3478", "0.0.0.0:3479"];

/// 逐个绑定 STUN 监听并启动应答循环（FR-8 / #76）。返回实际绑定的地址
/// （与入参一致，测试可用 127.0.0.1:0 拿临时端口）。非回环监听绑物理出口
/// 网卡（FR-7）；回环监听（测试）不绑——绑了物理网卡就收不到回环包。
pub async fn start_stun(listens: &[String]) -> anyhow::Result<Vec<SocketAddr>> {
    let mut bound = Vec::new();
    for listen in listens {
        let addr: SocketAddr = listen
            .parse()
            .map_err(|e| anyhow::anyhow!("无效的 STUN 监听地址 {listen}：{e}"))?;
        let sock = Arc::new(tokio::net::UdpSocket::bind(addr).await?);
        if !addr.ip().is_loopback() {
            hz_core::netif::bind_to_physical_egress(sock.as_ref());
        }
        bound.push(sock.local_addr()?);
        tokio::spawn(hz_core::stun::serve(sock));
    }
    tracing::info!(?bound, "stun servers listening");
    Ok(bound)
}

pub struct RelayConfig {
    pub listen: SocketAddr,
    pub tls: Option<ServerTlsConfig>,
    /// Coordination Server 地址（http:// 或 https://）。
    pub coord_addr: String,
    /// bootstrap 签发的 Relay Token。
    pub relay_token: String,
    /// 每 Node 的入口限速（Mbps）。桶容量为 1 秒额度。
    pub rate_limit_mbps: u64,
    /// Prometheus /metrics 监听地址；None 时不开指标面。
    pub metrics_listen: Option<SocketAddr>,
}

pub struct RelayHandle {
    pub local_addr: SocketAddr,
    shutdown: tokio::sync::watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
    metrics: Option<MetricsHandle>,
}

impl RelayHandle {
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        if let Some(metrics) = &self.metrics {
            metrics.shutdown();
        }
    }

    pub async fn terminated(self) {
        let _ = self.join.await;
        if let Some(metrics) = self.metrics {
            let _ = metrics.terminated().await;
        }
    }

    /// 指标面的实际监听地址（配置了 metrics_listen 时才有）。
    pub fn metrics_addr(&self) -> Option<SocketAddr> {
        self.metrics.as_ref().map(|metrics| metrics.local_addr)
    }
}

pub async fn serve_relay(config: RelayConfig) -> anyhow::Result<RelayHandle> {
    let coord = CoordClient::new(connect_coord(&config.coord_addr).await?);
    let metrics = Arc::new(Metrics::new()?);
    let metrics_handle = match config.metrics_listen {
        Some(listen) => Some(serve_metrics(listen, metrics.clone()).await?),
        None => None,
    };
    let service = RelayServiceImpl {
        sessions: Arc::new(SessionRegistry::default()),
        limiter: Arc::new(StdMutex::new(Limiter::new(config.rate_limit_mbps))),
        metrics,
        coord,
        relay_token: config.relay_token,
    };
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    let mut server = tonic::transport::Server::builder();
    if let Some(tls) = config.tls {
        server = server.tls_config(tls)?;
    }
    let router = server.add_service(RelayServer::new(service));
    let join = tokio::spawn(async move {
        tokio::select! {
            result = router.serve_with_incoming(TcpListenerStream::new(listener)) => {
                if let Err(error) = result {
                    tracing::error!(%error, "relay grpc server exited with error");
                }
            }
            _ = shutdown_rx.changed() => {
                tracing::info!("relay grpc server shut down by request");
            }
        }
    });
    tracing::info!(%local_addr, coord = %config.coord_addr, "relay grpc server listening");
    Ok(RelayHandle {
        local_addr,
        shutdown: shutdown_tx,
        join,
        metrics: metrics_handle,
    })
}

/// 到 Coordination Server 的懒连接：启动时 coord 未就绪也不阻塞 Relay，
/// 首次校验时才拨号；拨不通则校验失败（拒绝一切未验证客户端）。
async fn connect_coord(coord_addr: &str) -> anyhow::Result<Channel> {
    let endpoint =
        tonic::transport::Endpoint::from_shared(coord_addr.to_string()).map_err(|error| {
            anyhow::anyhow!("无效的 Coordination Server 地址 {coord_addr}：{error}")
        })?;
    let endpoint = match endpoint.uri().scheme_str() {
        Some("https") => endpoint.tls_config(tonic::transport::ClientTlsConfig::new())?,
        _ => endpoint,
    };
    Ok(endpoint.connect_lazy())
}

/// 已认证会话的登记表：node id → 该 Node 出向流的发送端。
#[derive(Default)]
struct SessionRegistry(StdMutex<HashMap<String, mpsc::Sender<Result<RelayFrame, Status>>>>);

fn error_frame(code: &str, message: &str) -> Result<RelayFrame, Status> {
    Ok(RelayFrame {
        kind: Some(relay_frame::Kind::Error(RelayError {
            code: code.to_owned(),
            message: message.to_owned(),
        })),
    })
}

struct RelayServiceImpl {
    sessions: Arc<SessionRegistry>,
    limiter: Arc<StdMutex<Limiter>>,
    metrics: Arc<Metrics>,
    coord: CoordClient<Channel>,
    relay_token: String,
}

/// 按登记表转发一帧数据；先过发送方的入口限速（FR-9），目标不在线时向
/// 发送端回 dst_not_connected。投递成功计入双向流量账，超额丢弃只记发送方。
fn forward_data(
    sessions: &SessionRegistry,
    limiter: &Arc<StdMutex<Limiter>>,
    metrics: &Arc<Metrics>,
    back: &mpsc::Sender<Result<RelayFrame, Status>>,
    src: &str,
    data: RelayData,
) {
    let dst_node_id = data.dst_node_id.clone();
    let len = data.payload.len();
    if !limiter
        .lock()
        .expect("limiter poisoned")
        .admit(src, len, Instant::now())
    {
        metrics.note_drop(src, len);
        tracing::debug!(src, %dst_node_id, len, "relay frame dropped by rate limit");
        return;
    }
    let Some(dst) = sessions
        .0
        .lock()
        .expect("sessions poisoned")
        .get(&dst_node_id)
        .cloned()
    else {
        tracing::debug!(src, %dst_node_id, "relay forward: destination not connected");
        let _ = back.try_send(error_frame(
            "dst_not_connected",
            &format!("目标 {dst_node_id} 未连接 Relay"),
        ));
        return;
    };
    let frame = RelayFrame {
        kind: Some(relay_frame::Kind::Data(data)),
    };
    if dst.try_send(Ok(frame)).is_err() {
        tracing::warn!(src, %dst_node_id, "relay session queue full or closed, dropping frame");
        return;
    }
    metrics.note_forward(src, &dst_node_id, len);
    tracing::debug!(src, %dst_node_id, len, "relay frame forwarded");
}

#[tonic::async_trait]
impl Relay for RelayServiceImpl {
    type RelayStreamStream = Pin<
        Box<dyn tonic::codegen::tokio_stream::Stream<Item = Result<RelayFrame, Status>> + Send>,
    >;

    async fn relay_stream(
        &self,
        request: Request<Streaming<RelayFrame>>,
    ) -> Result<Response<Self::RelayStreamStream>, Status> {
        let mut inbound = request.into_inner();
        let first = match tokio::time::timeout(HELLO_TIMEOUT, inbound.message()).await {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => return Err(Status::unauthenticated("流在认证前结束")),
            Ok(Err(error)) => {
                return Err(Status::unauthenticated(format!(
                    "读取 RelayHello 失败：{error}"
                )));
            }
            Err(_) => return Err(Status::unauthenticated("等待 RelayHello 超时")),
        };
        let Some(relay_frame::Kind::Hello(hello)) = first.kind else {
            return Err(Status::unauthenticated("首帧必须是 RelayHello"));
        };

        // tonic 客户端按调用克隆（Channel 复用同一连接池），trait 方法只有 &self。
        let mut coord = self.coord.clone();
        let check = coord
            .relay_check_node(RelayCheckRequest {
                relay_token: self.relay_token.clone(),
                node_id: hello.node_id.clone(),
                machine_key_pub: hello.machine_key_pub,
                challenge_nonce: hello.challenge_nonce,
                challenge_signature: hello.challenge_signature,
            })
            .await
            .map_err(|error| {
                Status::unavailable(format!("向 Coordination Server 校验失败：{error}"))
            })?
            .into_inner();

        let (tx, rx) = mpsc::channel::<Result<RelayFrame, Status>>(SESSION_DEPTH);
        if !check.valid {
            tracing::warn!(node_id = %hello.node_id, reason = %check.reason, "relay session rejected");
            let _ = tx.send(error_frame("unauthorized", &check.reason)).await;
            return Ok(Response::new(Box::pin(ReceiverStream::new(rx))));
        }

        let node_id = hello.node_id;
        self.sessions
            .0
            .lock()
            .expect("sessions poisoned")
            .insert(node_id.clone(), tx.clone());
        self.metrics.session_opened();
        tracing::info!(%node_id, "relay session opened");

        let sessions = self.sessions.clone();
        let limiter = self.limiter.clone();
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            loop {
                match inbound.message().await {
                    Ok(Some(frame)) => match frame.kind {
                        Some(relay_frame::Kind::Data(data)) => {
                            forward_data(&sessions, &limiter, &metrics, &tx, &node_id, data);
                        }
                        Some(relay_frame::Kind::Hello(_)) => {
                            tracing::warn!(%node_id, "duplicate hello, closing session");
                            break;
                        }
                        Some(relay_frame::Kind::Error(error)) => {
                            tracing::debug!(
                                %node_id,
                                code = %error.code,
                                "client signaled error, closing session"
                            );
                            break;
                        }
                        None => {}
                    },
                    Ok(None) => break,
                    Err(error) => {
                        tracing::debug!(%node_id, %error, "relay inbound ended");
                        break;
                    }
                }
            }
            let mut sessions = sessions.0.lock().expect("sessions poisoned");
            if sessions
                .get(&node_id)
                .is_some_and(|current| current.same_channel(&tx))
            {
                sessions.remove(&node_id);
                metrics.session_closed();
            }
            tracing::info!(%node_id, "relay session closed");
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}
