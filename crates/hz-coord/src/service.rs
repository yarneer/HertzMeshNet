//! gRPC 服务：挑战签发与校验、Auth Key 注册、交互式登录、协议版本闸门、
//! Network Map 下发流。下发流的登记在 [`crate::map_stream`]。
use std::net::{IpAddr, Shutdown, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hz_proto::MIN_SUPPORTED_PROTOCOL_VERSION;
use hz_proto::coord_server::{Coord, CoordServer};
use hz_proto::{
    AdminCreateAuthKeyRequest, AdminCreateAuthKeyResponse, AdminNodeInfo,
    AdminRevokeAuthKeyRequest, AdminRevokeAuthKeyResponse, BeginLoginRequest, BeginLoginResponse,
    DeleteNodeRequest, DeleteNodeResponse, HelloRequest, HelloResponse, ListNodesRequest,
    ListNodesResponse, LoginStatusRequest, LoginStatusResponse, NetworkMapMessage,
    PolicyGetRequest, PolicyGetResponse, PolicyPushRequest, PolicyPushResponse,
    PolicyRollbackRequest, PolicyRollbackResponse, PolicyVersionInfo, RegisterAuthKeyRequest,
    RegisterResponse, RelayCheckRequest, RelayCheckResponse, RenameNodeRequest, RenameNodeResponse,
    ReportEndpointsRequest, ReportEndpointsResponse, RevokeNodeRequest, RevokeNodeResponse,
    StreamMapRequest,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::ServerTlsConfig;
use tonic::{Request, Response, Status};

use crate::authkey;
use crate::challenge::{CHALLENGE_TTL, Challenge, ChallengeCache};
use crate::http::{DistConfig, DistState, HttpHandle, HttpState, serve_http};
use crate::login::{LOGIN_TTL, LoginRegistry, PollResult};
use crate::map_stream::{MapHub, MapPushConfig, node_info_from, run_fan_out};
use crate::metrics::{Metrics, MetricsHandle, serve_metrics};
use crate::oidc::{OidcClient, OidcConfig, new_login_token, new_pkce_verifier};
use crate::store::Store;
/// 下发流空差量保活间隔（FR-6 长连接）。
const MAP_KEEPALIVE: Duration = Duration::from_secs(30);
/// 全量重建间隔：接住到期跨越等没有 notify 信号的写入。
const MAP_SWEEP: Duration = Duration::from_secs(60);

/// 交互式登录授予的 Node 有效期（FR-3：默认 90 天）。
pub const LOGIN_NODE_TTL_SECS: i64 = 90 * 86_400;

pub struct ServeConfig {
    /// 同一个 Store 实例（克隆共享变更信号）：serve 侧与调用侧的写入
    /// 都要能唤醒 Map 推送任务。
    pub store: Store,
    pub listen: SocketAddr,
    pub tls: Option<ServerTlsConfig>,
    pub map_keepalive: Duration,
    pub map_sweep: Duration,
    /// 登录回调所在的 HTTP 面监听地址；配置了 OIDC 才有意义。
    pub http_listen: Option<SocketAddr>,
    pub oidc: Option<OidcConfig>,
    /// 分发面（FR-13）：配置后 install.sh 与 /dl 经 http_listen 下发。
    pub dist: Option<DistConfig>,
    /// Prometheus /metrics 监听地址；None 时不开指标面。
    pub metrics_listen: Option<SocketAddr>,
    /// 一次性登录链接的有效期（默认 5 分钟）。
    pub login_ttl: Duration,
    /// 交互式登录授予的 Node 有效期（默认 90 天）。
    pub login_node_ttl_secs: i64,
}

impl ServeConfig {
    pub fn new(store: Store, listen: SocketAddr) -> Self {
        Self {
            store,
            listen,
            tls: None,
            map_keepalive: MAP_KEEPALIVE,
            map_sweep: MAP_SWEEP,
            http_listen: None,
            oidc: None,
            dist: None,
            metrics_listen: None,
            login_ttl: LOGIN_TTL,
            login_node_ttl_secs: LOGIN_NODE_TTL_SECS,
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
    pub http_addr: Option<SocketAddr>,
    pub metrics_addr: Option<SocketAddr>,
    shutdown: tokio::sync::watch::Sender<bool>,
    http: Option<HttpHandle>,
    metrics: Option<MetricsHandle>,
    join: tokio::task::JoinHandle<()>,
    fan_out: tokio::task::JoinHandle<()>,
}

impl ServeHandle {
    pub fn shutdown(&self) {
        // 先停产生者再断连接：多线程运行时下 close_all 与 abort 之间没有
        // 原子性，中间新产出的帧仍可能被连接任务刷给客户端。
        self.fan_out.abort();
        self.connections.close_all();
        let _ = self.shutdown.send(true);
        if let Some(http) = &self.http {
            http.shutdown();
        }
        if let Some(metrics) = &self.metrics {
            metrics.shutdown();
        }
    }

    pub async fn terminated(self) {
        let _ = self.join.await;
        if let Some(http) = self.http {
            let _ = http.terminated().await;
        }
        if let Some(metrics) = self.metrics {
            let _ = metrics.terminated().await;
        }
    }
}

pub async fn serve(config: ServeConfig) -> anyhow::Result<ServeHandle> {
    let store = config.store;
    let hub = Arc::new(MapHub::new());

    let dist_state = match config.dist {
        Some(dist_config) => Some(Arc::new(DistState::build(&dist_config)?)),
        None => None,
    };
    // HTTP 面的两个用途（OIDC 回调、分发）只要配置了其一就要拉起。
    let (logins, http_handle) = if config.oidc.is_some() || dist_state.is_some() {
        let http_listen = config.http_listen.ok_or_else(|| {
            anyhow::anyhow!("配置了 OIDC 或 --dist-dir 但缺少 --http-listen，HTTP 面无处落地")
        })?;
        let oidc = match config.oidc {
            Some(oidc_config) => Some(OidcClient::discover(oidc_config).await?),
            None => None,
        };
        let logins = Arc::new(LoginRegistry::new());
        let http_state = Arc::new(HttpState {
            oidc,
            logins: logins.clone(),
            store: store.clone(),
            login_node_ttl_secs: config.login_node_ttl_secs,
            dist: dist_state,
        });
        let http = serve_http(http_listen, http_state).await?;
        (logins, Some(http))
    } else {
        (Arc::new(LoginRegistry::new()), None)
    };
    let http_addr = http_handle.as_ref().map(|http| http.local_addr);
    let metrics = Arc::new(Metrics::new()?);
    let metrics_handle = match config.metrics_listen {
        Some(listen) => Some(serve_metrics(listen, hub.clone(), metrics.clone()).await?),
        None => None,
    };
    let metrics_addr = metrics_handle.as_ref().map(|metrics| metrics.local_addr);
    let service = CoordServiceImpl {
        store: store.clone(),
        challenges: ChallengeCache::new(),
        map_hub: hub.clone(),
        logins: logins.clone(),
        login_ttl: config.login_ttl,
        http_addr,
        metrics,
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
        http: http_handle,
        http_addr,
        metrics: metrics_handle,
        metrics_addr,
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
    logins: Arc<LoginRegistry>,
    login_ttl: Duration,
    http_addr: Option<SocketAddr>,
    metrics: Arc<Metrics>,
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

    /// 挑战的取走 + 签名校验；Hello 之后的每个需要认证的 rpc 共用。
    fn take_verified_challenge(
        challenges: &ChallengeCache,
        req_machine_key_pub: &[u8],
        req_hostname: &str,
        nonce: [u8; 32],
        signature: [u8; 64],
    ) -> Result<Challenge, Status> {
        let challenge = challenges
            .take(&nonce)
            .ok_or_else(|| Status::permission_denied("挑战不存在或已过期，请重新发起注册"))?;
        if challenge.expires <= std::time::Instant::now() {
            return Err(Status::permission_denied(
                "挑战不存在或已过期，请重新发起注册",
            ));
        }
        if challenge.machine_key_pub != req_machine_key_pub || challenge.hostname != req_hostname {
            return Err(Status::unauthenticated(
                "签名验证失败：挑战与请求的 Machine Key 或主机名不匹配",
            ));
        }
        let verifying_key = VerifyingKey::from_bytes(&challenge.machine_key_pub)
            .map_err(|_| Status::unauthenticated("签名验证失败：Machine Key 公钥无效"))?;
        verifying_key
            .verify(&nonce, &Signature::from_bytes(&signature))
            .map_err(|_| Status::unauthenticated("签名验证失败"))?;
        Ok(challenge)
    }

    /// 需认证 rpc 的共用前置：挑战认证 + Node 在册且未过期。
    /// Policy（#13）与 Admin 管理（#12）rpc 都从这里进。
    async fn authenticate_node_caller(
        &self,
        req_protocol_version: u32,
        req_machine_key_pub: &[u8],
        req_hostname: &str,
        req_challenge_nonce: &[u8],
        req_challenge_signature: &[u8],
    ) -> Result<crate::store::NodeRecord, Status> {
        if let Some(status) = Self::hello_reject_old_version(req_protocol_version) {
            return Err(status);
        }
        let machine_key_pub: [u8; 32] = req_machine_key_pub
            .try_into()
            .map_err(|_| Status::invalid_argument("machine_key_pub 必须是 32 字节"))?;
        let nonce: [u8; 32] = req_challenge_nonce
            .try_into()
            .map_err(|_| Status::invalid_argument("challenge_nonce 必须是 32 字节"))?;
        let signature: [u8; 64] = req_challenge_signature
            .try_into()
            .map_err(|_| Status::invalid_argument("challenge_signature 必须是 64 字节"))?;
        Self::take_verified_challenge(
            &self.challenges,
            &machine_key_pub,
            req_hostname,
            nonce,
            signature,
        )?;
        let record = self
            .store
            .node_by_machine_key(&machine_key_pub)
            .await
            .map_err(|e| {
                tracing::error!(%e, "lookup node for policy rpc failed");
                Status::internal("查询 Node 失败")
            })?
            .ok_or_else(|| Status::permission_denied("Node 未注册或已吊销"))?;
        if record
            .expires_at_unix
            .is_some_and(|expires| expires <= crate::store::unix_now())
        {
            return Err(Status::permission_denied("Node 已过期，请重新登录"));
        }
        Ok(record)
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

        // Auth Key 注册同时是已注册 Node 的密钥刷新通道；过期的 Node 不得借此
        // 续命（FR-3：重新登录才是恢复路径）。先于 Auth Key 消费判定，
        // 一次性 Key 不为注定失败的注册买单。
        if let Some(existing) = self
            .store
            .node_by_machine_key(&challenge.machine_key_pub)
            .await
            .map_err(|e| {
                tracing::error!(%e, "lookup node for registration failed");
                Status::internal("注册失败：服务端存储错误")
            })?
        {
            if existing
                .expires_at_unix
                .is_some_and(|expires| expires <= crate::store::unix_now())
            {
                tracing::warn!(node_id = %existing.id, "auth key registration rejected: node expired");
                return Err(Status::permission_denied("Node 已过期，请重新登录"));
            }
        }

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
        let range = self.store.range_fields();
        Ok(Response::new(RegisterResponse {
            node: Some(node_info_from(record)),
            network_cidr: range.0,
            dns_v4: range.1,
        }))
    }

    async fn begin_interactive_login(
        &self,
        request: Request<BeginLoginRequest>,
    ) -> Result<Response<BeginLoginResponse>, Status> {
        let req = request.into_inner();
        if let Some(status) = Self::hello_reject_old_version(req.protocol_version) {
            return Err(status);
        }
        let Some(http_addr) = self.http_addr else {
            return Err(Status::unimplemented(
                "此 Coordination Server 未配置交互式登录（OIDC）",
            ));
        };
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
        let challenge = Self::take_verified_challenge(
            &self.challenges,
            &machine_key_pub,
            &req.hostname,
            nonce,
            signature,
        )?;

        let started = self.logins.begin(
            challenge.machine_key_pub,
            challenge.hostname,
            req.node_key_pub,
            new_login_token("n-"),
            new_pkce_verifier(),
            self.login_ttl,
        );
        let started = started.map_err(Status::failed_precondition)?;
        let expires_unix =
            system_time_to_unix(SystemTime::now() + self.login_ttl.max(Duration::ZERO));
        tracing::info!(
            login_id = %started.login_id.0,
            "interactive login began"
        );
        Ok(Response::new(BeginLoginResponse {
            login_url: format!("http://{http_addr}/oidc/start/{}", started.login_id.0),
            expires_unix,
        }))
    }

    async fn login_status(
        &self,
        request: Request<LoginStatusRequest>,
    ) -> Result<Response<LoginStatusResponse>, Status> {
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
        Self::take_verified_challenge(
            &self.challenges,
            &machine_key_pub,
            &req.hostname,
            nonce,
            signature,
        )?;

        let range = self.store.range_fields();
        match self.logins.poll(&req.login_id, &machine_key_pub) {
            PollResult::Pending => Ok(Response::new(LoginStatusResponse {
                completed: false,
                node: None,
                error: None,
                network_cidr: range.0,
                dns_v4: range.1,
            })),
            PollResult::Completed(record) => {
                tracing::info!(node_id = %record.id, "interactive login delivered to node");
                Ok(Response::new(LoginStatusResponse {
                    completed: true,
                    node: Some(node_info_from(record)),
                    error: None,
                    network_cidr: Some(self.store.addr().cidr.to_string()),
                    dns_v4: Some(self.store.addr().reserved_dns().to_string()),
                }))
            }
            PollResult::Failed(reason) => Ok(Response::new(LoginStatusResponse {
                completed: true,
                node: None,
                error: Some(reason),
                network_cidr: range.0,
                dns_v4: range.1,
            })),
        }
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
            let stored = endpoints
                .iter()
                .map(|addr| crate::store::StoredEndpoint::lan(addr.clone()))
                .collect::<Vec<_>>();
            self.store
                .update_udp_endpoints(&record.id, &stored)
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

        let Some(record) = self
            .store
            .node_by_machine_key(&machine_key_pub)
            .await
            .map_err(|error| {
                tracing::error!(%error, "lookup node for relay check failed");
                Status::internal("查询 Node 失败")
            })?
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

    /// Endpoint 上报（FR-8）：挑战认证通过后整体覆盖该 Node 的 Endpoint 列表，
    /// 存储变更唤醒 fan-out，其他 Node 收到差量。打洞信令不经这里。
    async fn report_endpoints(
        &self,
        request: Request<ReportEndpointsRequest>,
    ) -> Result<Response<ReportEndpointsResponse>, Status> {
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
        Self::take_verified_challenge(
            &self.challenges,
            &machine_key_pub,
            &req.hostname,
            nonce,
            signature,
        )?;

        let record = self
            .store
            .node_by_machine_key(&machine_key_pub)
            .await
            .map_err(|e| {
                tracing::error!(%e, "lookup node for endpoint report failed");
                Status::internal("查询 Node 失败")
            })?
            .ok_or_else(|| Status::permission_denied("Node 未注册或已吊销，无法上报 Endpoint"))?;
        if record
            .expires_at_unix
            .is_some_and(|expires| expires <= crate::store::unix_now())
        {
            return Err(Status::permission_denied("Node 已过期，请重新登录"));
        }

        // 边界输入：addr 必须是 IP 字面量、port 在范围内、kind 未知按 lan 兜底。
        let stored = req
            .endpoints
            .iter()
            .map(|endpoint| {
                let addr: IpAddr = endpoint.addr.parse().map_err(|_| {
                    Status::invalid_argument(format!(
                        "无效的 Endpoint 地址：{}，期望 IP 字面量",
                        endpoint.addr
                    ))
                })?;
                if endpoint.port == 0 || endpoint.port > u16::MAX as u32 {
                    return Err(Status::invalid_argument(format!(
                        "无效的 Endpoint 端口：{}",
                        endpoint.port
                    )));
                }
                let kind = hz_proto::EndpointKind::try_from(endpoint.kind)
                    .map(|kind| match kind {
                        hz_proto::EndpointKind::Stun => "stun",
                        hz_proto::EndpointKind::V6 => "v6",
                        _ => "lan",
                    })
                    .unwrap_or("lan");
                Ok(crate::store::StoredEndpoint::of_kind(
                    SocketAddr::new(addr, endpoint.port as u16).to_string(),
                    kind,
                ))
            })
            .collect::<Result<Vec<_>, Status>>()?;

        tracing::info!(node_id = %record.id, ?stored, "node endpoints reported");
        if let Some(report) = req.path_report {
            self.metrics.note_path_report(
                &record.id,
                report.punch_attempts as u64,
                report.punch_success as u64,
            );
        }
        self.store
            .update_udp_endpoints(&record.id, &stored)
            .await
            .map_err(|e| {
                tracing::error!(%e, "update reported endpoints failed");
                Status::internal("更新 Endpoint 失败")
            })?;
        Ok(Response::new(ReportEndpointsResponse {}))
    }

    /// Policy 整份替换（FR-10）：Admin 授权 → 完整校验（失败整份拒绝）→
    /// 入库新版本并唤醒 Map 重算（受影响 Node 秒级收到新视图）。
    async fn policy_push(
        &self,
        request: Request<PolicyPushRequest>,
    ) -> Result<Response<PolicyPushResponse>, Status> {
        let req = request.into_inner();
        let record = self
            .authenticate_node_caller(
                req.protocol_version,
                &req.machine_key_pub,
                &req.hostname,
                &req.challenge_nonce,
                &req.challenge_signature,
            )
            .await?;
        crate::policy::authorize_admin(&self.store, &record).await?;

        crate::policy::validate_policy(&self.store, &req.content).await?;
        let version = self.store.push_policy(&req.content).await.map_err(|e| {
            tracing::error!(%e, "store policy failed");
            Status::internal("Policy 入库失败")
        })?;
        tracing::info!(node_id = %record.id, version, "policy pushed");
        Ok(Response::new(PolicyPushResponse { version }))
    }

    /// 查看当前 Policy 与历史版本（FR-10）。只读，注册 Node 即可调用。
    async fn policy_get(
        &self,
        request: Request<PolicyGetRequest>,
    ) -> Result<Response<PolicyGetResponse>, Status> {
        let req = request.into_inner();
        self.authenticate_node_caller(
            req.protocol_version,
            &req.machine_key_pub,
            &req.hostname,
            &req.challenge_nonce,
            &req.challenge_signature,
        )
        .await?;

        let (version, content) = match self.store.current_policy().await.map_err(|e| {
            tracing::error!(%e, "load current policy failed");
            Status::internal("读取 Policy 失败")
        })? {
            Some((version, content)) => (version, Some(content)),
            None => (0, None),
        };
        let history = self
            .store
            .policy_history()
            .await
            .map_err(|e| {
                tracing::error!(%e, "load policy history failed");
                Status::internal("读取 Policy 历史失败")
            })?
            .into_iter()
            .map(|row| PolicyVersionInfo {
                version: row.version,
                created_at_unix: row.created_at_unix,
            })
            .collect();
        Ok(Response::new(PolicyGetResponse {
            content,
            version,
            history,
        }))
    }

    /// 回滚到历史版本：内容按当前 users 表重新校验（引用可能已失效），
    /// 失败拒绝并保持现行版本不变。
    async fn policy_rollback(
        &self,
        request: Request<PolicyRollbackRequest>,
    ) -> Result<Response<PolicyRollbackResponse>, Status> {
        let req = request.into_inner();
        let record = self
            .authenticate_node_caller(
                req.protocol_version,
                &req.machine_key_pub,
                &req.hostname,
                &req.challenge_nonce,
                &req.challenge_signature,
            )
            .await?;
        crate::policy::authorize_admin(&self.store, &record).await?;

        let content = self
            .store
            .policy_version_content(req.version)
            .await
            .map_err(|e| {
                tracing::error!(%e, "load policy version for rollback failed");
                Status::internal("读取 Policy 版本失败")
            })?
            .ok_or_else(|| {
                Status::invalid_argument(format!("版本 {} 不存在，无法回滚", req.version))
            })?;
        crate::policy::validate_policy(&self.store, &content).await?;
        self.store.rollback_policy(req.version).await.map_err(|e| {
            tracing::error!(%e, "rollback policy failed");
            Status::internal("Policy 回滚失败")
        })?;
        tracing::info!(node_id = %record.id, version = req.version, "policy rolled back");
        Ok(Response::new(PolicyRollbackResponse {
            version: req.version,
        }))
    }

    // ---- Admin 远程管理（FR-11 / #12）：认证 → 解析操作者 → 权限表 → 业务。----

    async fn admin_create_auth_key(
        &self,
        request: Request<AdminCreateAuthKeyRequest>,
    ) -> Result<Response<AdminCreateAuthKeyResponse>, Status> {
        let req = request.into_inner();
        let record = self
            .authenticate_node_caller(
                req.protocol_version,
                &req.machine_key_pub,
                &req.hostname,
                &req.challenge_nonce,
                &req.challenge_signature,
            )
            .await?;
        let operator = crate::admin::resolve_operator(&self.store, &record).await?;
        crate::admin::require_admin(&operator)?;
        let (auth_key, key_id) =
            crate::admin::create_auth_key(&self.store, req.expires_unix, req.single_use, &req.tags)
                .await?;
        tracing::info!(node_id = %record.id, key_id, "auth key issued via admin rpc");
        Ok(Response::new(AdminCreateAuthKeyResponse {
            auth_key,
            key_id,
        }))
    }

    async fn admin_revoke_auth_key(
        &self,
        request: Request<AdminRevokeAuthKeyRequest>,
    ) -> Result<Response<AdminRevokeAuthKeyResponse>, Status> {
        let req = request.into_inner();
        let record = self
            .authenticate_node_caller(
                req.protocol_version,
                &req.machine_key_pub,
                &req.hostname,
                &req.challenge_nonce,
                &req.challenge_signature,
            )
            .await?;
        let operator = crate::admin::resolve_operator(&self.store, &record).await?;
        crate::admin::require_admin(&operator)?;
        crate::admin::revoke_auth_key(&self.store, &req.key_id).await?;
        tracing::info!(node_id = %record.id, key_id = %req.key_id, "auth key revoked via admin rpc");
        Ok(Response::new(AdminRevokeAuthKeyResponse {}))
    }

    async fn list_nodes(
        &self,
        request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        let req = request.into_inner();
        let record = self
            .authenticate_node_caller(
                req.protocol_version,
                &req.machine_key_pub,
                &req.hostname,
                &req.challenge_nonce,
                &req.challenge_signature,
            )
            .await?;
        let operator = crate::admin::resolve_operator(&self.store, &record).await?;
        let scope = crate::admin::list_scope(&operator)?;
        let nodes = self
            .store
            .list_nodes(&scope)
            .await
            .map_err(|e| {
                tracing::error!(%e, "list nodes failed");
                Status::internal("列出 Node 失败")
            })?
            .into_iter()
            .map(|row| AdminNodeInfo {
                node_id: row.node_id,
                name: row.name,
                ipv4: row.ipv4,
                ipv6: row.ipv6,
                tags: row.tags,
                owner_user: row.owner_user,
                expires_at_unix: row.expires_at_unix,
                revoked: row.revoked,
            })
            .collect();
        Ok(Response::new(ListNodesResponse { nodes }))
    }

    async fn rename_node(
        &self,
        request: Request<RenameNodeRequest>,
    ) -> Result<Response<RenameNodeResponse>, Status> {
        let req = request.into_inner();
        let record = self
            .authenticate_node_caller(
                req.protocol_version,
                &req.machine_key_pub,
                &req.hostname,
                &req.challenge_nonce,
                &req.challenge_signature,
            )
            .await?;
        let operator = crate::admin::resolve_operator(&self.store, &record).await?;
        let name =
            crate::admin::rename_node(&self.store, &operator, &req.node_id, &req.new_name).await?;
        Ok(Response::new(RenameNodeResponse { name }))
    }

    async fn delete_node(
        &self,
        request: Request<DeleteNodeRequest>,
    ) -> Result<Response<DeleteNodeResponse>, Status> {
        let req = request.into_inner();
        let record = self
            .authenticate_node_caller(
                req.protocol_version,
                &req.machine_key_pub,
                &req.hostname,
                &req.challenge_nonce,
                &req.challenge_signature,
            )
            .await?;
        let operator = crate::admin::resolve_operator(&self.store, &record).await?;
        crate::admin::delete_node(&self.store, &operator, &req.node_id).await?;
        tracing::info!(node_id = %req.node_id, by = %record.id, "node deleted via admin rpc");
        Ok(Response::new(DeleteNodeResponse {}))
    }

    async fn revoke_node(
        &self,
        request: Request<RevokeNodeRequest>,
    ) -> Result<Response<RevokeNodeResponse>, Status> {
        let req = request.into_inner();
        let record = self
            .authenticate_node_caller(
                req.protocol_version,
                &req.machine_key_pub,
                &req.hostname,
                &req.challenge_nonce,
                &req.challenge_signature,
            )
            .await?;
        let operator = crate::admin::resolve_operator(&self.store, &record).await?;
        crate::admin::require_admin(&operator)?;
        crate::admin::revoke_node(&self.store, &req.node_id).await?;
        Ok(Response::new(RevokeNodeResponse {}))
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
