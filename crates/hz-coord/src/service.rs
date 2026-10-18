//! gRPC 服务：挑战签发与校验、Auth Key 注册、协议版本闸门、Network Map 下发流。
//! BeginInteractiveLogin 只定义接口（#10 实现）；下发流的登记在 [`crate::map_stream`]。

use std::net::{Shutdown, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hz_proto::MIN_SUPPORTED_PROTOCOL_VERSION;
use hz_proto::coord_server::{Coord, CoordServer};
use hz_proto::{
    BeginLoginRequest, BeginLoginResponse, HelloRequest, HelloResponse, NetworkMapMessage,
    RegisterAuthKeyRequest, RegisterResponse, RelayCheckRequest, RelayCheckResponse,
    StreamMapRequest,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::ServerTlsConfig;
use tonic::{Request, Response, Status};

use crate::authkey;
use crate::challenge::{CHALLENGE_TTL, ChallengeCache};
use crate::map_stream::{MapHub, MapPushConfig, node_info_from, run_fan_out};
use crate::store::Store;

/// 下发流空差量保活间隔（FR-6 长连接）。
const MAP_KEEPALIVE: Duration = Duration::from_secs(30);
/// 全量重建间隔：接住到期跨越等没有 notify 信号的写入。
const MAP_SWEEP: Duration = Duration::from_secs(60);

pub struct ServeConfig {
    /// 同一个 Store 实例（克隆共享变更信号）：serve 侧与调用侧的写入
    /// 都要能唤醒 Map 推送任务。
    pub store: Store,
    pub listen: SocketAddr,
    pub tls: Option<ServerTlsConfig>,
    pub map_keepalive: Duration,
    pub map_sweep: Duration,
}

impl ServeConfig {
    pub fn new(store: Store, listen: SocketAddr) -> Self {
        Self {
            store,
            listen,
            tls: None,
            map_keepalive: MAP_KEEPALIVE,
            map_sweep: MAP_SWEEP,
        }
    }
}

/// 已建连接的登记表：shutdown 时对每条连接直接 RST/FIN。
/// 光停 listener 杀不掉已建立的 gRPC 长连接，Map 流会一直挂着。
#[derive(Default)]
struct LiveConnections(StdMutex<Vec<std::net::TcpStream>>);

impl LiveConnections {
    fn track(&self, stream: &tokio::net::TcpStream) {
        use std::os::fd::{AsRawFd, FromRawFd};
        // dup 出独立描述符；tonic 继续持有原流，关闭动作只作用在副本上。
        let duplicate = unsafe { libc::dup(stream.as_raw_fd()) };
        if duplicate >= 0 {
            let raw = unsafe { std::net::TcpStream::from_raw_fd(duplicate) };
            self.0.lock().expect("live connections poisoned").push(raw);
        }
    }

    fn close_all(&self) {
        for stream in self.0.lock().expect("live connections poisoned").drain(..) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

pub struct ServeHandle {
    pub local_addr: SocketAddr,
    connections: Arc<LiveConnections>,
    shutdown: tokio::sync::watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
    fan_out: tokio::task::JoinHandle<()>,
}

impl ServeHandle {
    pub fn shutdown(&self) {
        self.connections.close_all();
        let _ = self.shutdown.send(true);
        self.fan_out.abort();
    }

    pub async fn terminated(self) {
        let _ = self.join.await;
    }
}

pub async fn serve(config: ServeConfig) -> anyhow::Result<ServeHandle> {
    let store = config.store;
    let hub = Arc::new(MapHub::new());
    let service = CoordServiceImpl {
        store: store.clone(),
        challenges: ChallengeCache::new(),
        map_hub: hub.clone(),
    };
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    let fan_out = tokio::spawn(run_fan_out(
        store,
        hub,
        MapPushConfig {
            keepalive_every: config.map_keepalive,
            sweep_every: config.map_sweep,
        },
    ));

    let mut server = tonic::transport::Server::builder();
    if let Some(tls) = config.tls {
        server = server.tls_config(tls)?;
    }
    let router = server.add_service(CoordServer::new(service));
    let connections = Arc::new(LiveConnections::default());
    let tracked = {
        let connections = connections.clone();
        TcpListenerStreamMapped::new(listener, connections)
    };
    let join = tokio::spawn(async move {
        tokio::select! {
            result = router.serve_with_incoming(tracked) => {
                if let Err(error) = result {
                    tracing::error!(%error, "coord grpc server exited with error");
                }
            }
            _ = shutdown_rx.changed() => {
                tracing::info!("coord grpc server shut down by request");
            }
        }
    });
    tracing::info!(%local_addr, "coord grpc server listening");
    Ok(ServeHandle {
        local_addr,
        connections,
        shutdown: shutdown_tx,
        join,
        fan_out,
    })
}

/// 每条已接受的连接登记进 LiveConnections 后原样交给 tonic。
struct TcpListenerStreamMapped {
    listener: tokio::net::TcpListener,
    connections: Arc<LiveConnections>,
}

impl TcpListenerStreamMapped {
    fn new(listener: tokio::net::TcpListener, connections: Arc<LiveConnections>) -> Self {
        Self {
            listener,
            connections,
        }
    }
}

impl tokio_stream::Stream for TcpListenerStreamMapped {
    type Item = std::io::Result<tokio::net::TcpStream>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // TcpListener 是 Unpin 的，这里可以直接拿可变引用。
        let this = self.get_mut();
        match this.listener.poll_accept(cx) {
            std::task::Poll::Ready(Ok((stream, _))) => {
                this.connections.track(&stream);
                std::task::Poll::Ready(Some(Ok(stream)))
            }
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Some(Err(error))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

struct CoordServiceImpl {
    store: Store,
    challenges: ChallengeCache,
    map_hub: Arc<MapHub>,
}

impl CoordServiceImpl {
    fn hello_reject_old_version(protocol_version: u32) -> Option<Status> {
        (protocol_version < MIN_SUPPORTED_PROTOCOL_VERSION).then(|| {
            Status::failed_precondition(format!(
                "客户端版本过旧：协议版本 {protocol_version} 低于最低支持版本 \
                 {MIN_SUPPORTED_PROTOCOL_VERSION}，请升级 hzd 后重试"
            ))
        })
    }
}

#[tonic::async_trait]
impl Coord for CoordServiceImpl {
    async fn hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloResponse>, Status> {
        let req = request.into_inner();
        if let Some(status) = Self::hello_reject_old_version(req.protocol_version) {
            return Err(status);
        }
        let machine_key_pub: [u8; 32] = req
            .machine_key_pub
            .try_into()
            .map_err(|_| Status::invalid_argument("machine_key_pub 必须是 32 字节"))?;
        let (nonce, _expires) = self.challenges.issue(machine_key_pub, req.hostname);
        let challenge_expires_unix = system_time_to_unix(SystemTime::now() + CHALLENGE_TTL);
        Ok(Response::new(HelloResponse {
            challenge_nonce: nonce.to_vec(),
            challenge_expires_unix,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }

    async fn register_with_auth_key(
        &self,
        request: Request<RegisterAuthKeyRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();

        let nonce: [u8; 32] = req
            .challenge_nonce
            .try_into()
            .map_err(|_| Status::invalid_argument("challenge_nonce 必须是 32 字节"))?;
        let signature: [u8; 64] = req
            .challenge_signature
            .try_into()
            .map_err(|_| Status::invalid_argument("challenge_signature 必须是 64 字节"))?;
        let node_key_pub: [u8; 32] = req
            .node_key_pub
            .try_into()
            .map_err(|_| Status::invalid_argument("node_key_pub 必须是 32 字节"))?;

        let challenge = self
            .challenges
            .take(&nonce)
            .ok_or_else(|| Status::permission_denied("挑战不存在或已过期，请重新发起注册"))?;
        if challenge.expires <= std::time::Instant::now() {
            return Err(Status::permission_denied(
                "挑战不存在或已过期，请重新发起注册",
            ));
        }

        let verifying_key = VerifyingKey::from_bytes(&challenge.machine_key_pub)
            .map_err(|_| Status::unauthenticated("签名验证失败：Machine Key 公钥无效"))?;
        verifying_key
            .verify(&nonce, &Signature::from_bytes(&signature))
            .map_err(|_| Status::unauthenticated("签名验证失败"))?;

        let tags = self
            .store
            .consume_auth_key(&req.auth_key)
            .await
            .map_err(|error| Status::permission_denied(error.to_string()))?;
        let record = self
            .store
            .register_node(
                &challenge.machine_key_pub,
                &node_key_pub,
                &challenge.hostname,
                &tags,
                None,
                None,
            )
            .await
            .map_err(|error| {
                tracing::error!(%error, "node registration failed");
                Status::internal("注册失败：服务端存储错误")
            })?;

        tracing::info!(node_id = %record.id, name = %record.name, "node registered");
        Ok(Response::new(RegisterResponse {
            node: Some(node_info_from(record)),
        }))
    }

    async fn begin_interactive_login(
        &self,
        _request: Request<BeginLoginRequest>,
    ) -> Result<Response<BeginLoginResponse>, Status> {
        Err(Status::unimplemented("交互式登录尚未实现"))
    }

    type StreamNetworkMapStream = Pin<
        Box<
            dyn tonic::codegen::tokio_stream::Stream<Item = Result<NetworkMapMessage, Status>>
                + Send,
        >,
    >;

    async fn stream_network_map(
        &self,
        request: Request<StreamMapRequest>,
    ) -> Result<Response<Self::StreamNetworkMapStream>, Status> {
        let req = request.into_inner();
        if let Some(status) = Self::hello_reject_old_version(req.protocol_version) {
            return Err(status);
        }
        let machine_key_pub: [u8; 32] = req
            .machine_key_pub
            .try_into()
            .map_err(|_| Status::invalid_argument("machine_key_pub 必须是 32 字节"))?;
        let nonce: [u8; 32] = req
            .challenge_nonce
            .try_into()
            .map_err(|_| Status::invalid_argument("challenge_nonce 必须是 32 字节"))?;
        let signature: [u8; 64] = req
            .challenge_signature
            .try_into()
            .map_err(|_| Status::invalid_argument("challenge_signature 必须是 64 字节"))?;

        let challenge = self
            .challenges
            .take(&nonce)
            .ok_or_else(|| Status::permission_denied("挑战不存在或已过期，请重新发起"))?;
        if challenge.machine_key_pub != machine_key_pub {
            return Err(Status::unauthenticated("签名验证失败：挑战与公钥不匹配"));
        }
        let verifying_key = VerifyingKey::from_bytes(&machine_key_pub)
            .map_err(|_| Status::unauthenticated("签名验证失败：Machine Key 公钥无效"))?;
        verifying_key
            .verify(&nonce, &Signature::from_bytes(&signature))
            .map_err(|_| Status::unauthenticated("签名验证失败"))?;

        let record = self
            .store
            .node_by_machine_key(&machine_key_pub)
            .await
            .map_err(|e| {
                tracing::error!(%e, "lookup node for map stream failed");
                Status::internal("查询 Node 失败")
            })?
            .ok_or_else(|| {
                Status::permission_denied("Node 未注册或已吊销，无法下发 Network Map")
            })?;
        if record
            .expires_at_unix
            .is_some_and(|expires| expires <= crate::store::unix_now())
        {
            return Err(Status::permission_denied("Node 已过期，请重新登录"));
        }

        // Endpoint 是边界输入：逐条解析成 SocketAddr，坏一条就拒绝整份上报。
        let endpoints = parse_endpoints(&req.endpoints)?;
        if !endpoints.is_empty() {
            self.store
                .update_udp_endpoints(&record.id, &endpoints)
                .await
                .map_err(|e| {
                    tracing::error!(%e, "update udp endpoints failed");
                    Status::internal("更新 Endpoint 失败")
                })?;
            tracing::info!(node_id = %record.id, ?endpoints, "node endpoints updated");
        }

        // 打开即登记进推送枢纽；首条全量快照与后续差量都由 fan-out 任务按序投递，
        // 接收端断开时投递失败、登记随之移除。
        let rx = self.map_hub.register(record.id.clone());
        tracing::info!(node_id = %record.id, "network map stream opened");
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    /// Relay 代理的 Node 身份校验（FR-9）。relay token 与 Machine-Key 挑战签名
    /// 都是边界输入：任何一项不符都拒绝，不区分具体原因细节以防探测。
    async fn relay_check_node(
        &self,
        request: Request<RelayCheckRequest>,
    ) -> Result<Response<RelayCheckResponse>, Status> {
        let req = request.into_inner();

        let expected = self.store.relay_token_hash().await.map_err(|error| {
            tracing::error!(%error, "lookup relay token hash failed");
            Status::internal("查询 Relay Token 失败")
        })?;
        let token_matches = expected.is_some_and(|hash| {
            constant_time_eq(authkey::hash(&req.relay_token).as_bytes(), hash.as_bytes())
        });
        if !token_matches {
            tracing::warn!("relay check rejected: invalid relay token");
            return Ok(Response::new(RelayCheckResponse {
                valid: false,
                reason: "Relay Token 无效".to_string(),
            }));
        }

        let machine_key_pub: [u8; 32] = match req.machine_key_pub.try_into() {
            Ok(key) => key,
            Err(_) => {
                return Ok(rejected("Machine Key 公钥格式无效"));
            }
        };
        let signature: [u8; 64] = match req.challenge_signature.try_into() {
            Ok(sig) => sig,
            Err(_) => return Ok(rejected("挑战签名格式无效")),
        };

        let Some(record) = self.store.node_by_machine_key(&machine_key_pub).await.map_err(
            |error| {
                tracing::error!(%error, "lookup node for relay check failed");
                Status::internal("查询 Node 失败")
            },
        )?
        else {
            return Ok(rejected("Node 未注册或已吊销"));
        };
        if record.id != req.node_id {
            return Ok(rejected("node_id 与 Machine Key 不匹配"));
        }
        if record
            .expires_at_unix
            .is_some_and(|expires| expires <= crate::store::unix_now())
        {
            return Ok(rejected("Node 已过期"));
        }

        let verifying_key = VerifyingKey::from_bytes(&machine_key_pub)
            .map_err(|_| Status::unauthenticated("签名验证失败：Machine Key 公钥无效"))?;
        let nonce: [u8; 32] = req
            .challenge_nonce
            .try_into()
            .map_err(|_| Status::invalid_argument("challenge_nonce 必须是 32 字节"))?;
        if verifying_key
            .verify(&nonce, &Signature::from_bytes(&signature))
            .is_err()
        {
            return Ok(rejected("签名验证失败"));
        }

        tracing::info!(node_id = %record.id, "relay check passed");
        Ok(Response::new(RelayCheckResponse {
            valid: true,
            reason: String::new(),
        }))
    }
}

fn rejected(reason: &str) -> Response<RelayCheckResponse> {
    tracing::warn!(reason, "relay check rejected");
    Response::new(RelayCheckResponse {
        valid: false,
        reason: reason.to_string(),
    })
}

/// Relay Token 与库中哈希的定长（sha256 hex，64 字节）比较，不短路。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 校验并规范化 Endpoint 上报；空列表合法（Node 还没拿到地址）。
fn parse_endpoints(raw: &[String]) -> Result<Vec<String>, Status> {
    raw.iter()
        .map(|endpoint| {
            endpoint
                .parse::<SocketAddr>()
                .map(|addr| addr.to_string())
                .map_err(|_| {
                    Status::invalid_argument(format!("无效的 Endpoint：{endpoint}，期望 ip:port"))
                })
        })
        .collect()
}

fn system_time_to_unix(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parsing_accepts_ip_port_and_rejects_garbage() {
        assert_eq!(
            parse_endpoints(&["192.168.1.2:51820".to_string()]).unwrap(),
            vec!["192.168.1.2:51820".to_string()]
        );
        assert_eq!(parse_endpoints(&[]).unwrap(), Vec::<String>::new());
        assert!(parse_endpoints(&["not-an-endpoint".to_string()]).is_err());
        assert!(parse_endpoints(&["192.168.1.2".to_string()]).is_err());
    }

    #[test]
    fn constant_time_eq_matches_only_equal_length_equal_bytes() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
