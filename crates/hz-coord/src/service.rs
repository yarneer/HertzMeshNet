//! gRPC 服务：挑战签发与校验、Auth Key 注册、交互式登录、协议版本闸门、
//! Network Map 快照流。Map 增量推送与断线重连在 #6。

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hz_proto::MIN_SUPPORTED_PROTOCOL_VERSION;
use hz_proto::coord_server::{Coord, CoordServer};
use hz_proto::{
    BeginLoginRequest, BeginLoginResponse, HelloRequest, HelloResponse, LoginStatusRequest,
    LoginStatusResponse, NetworkMapMessage, NodeInfo, RegisterAuthKeyRequest, RegisterResponse,
    StreamMapRequest,
};
use sqlx::SqlitePool;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::ServerTlsConfig;
use tonic::{Request, Response, Status};

use crate::addr::AddressConfig;
use crate::challenge::{CHALLENGE_TTL, Challenge, ChallengeCache};
use crate::http::{HttpHandle, HttpState, serve_http};
use crate::login::{LOGIN_TTL, LoginRegistry, PollResult};
use crate::oidc::{OidcClient, OidcConfig, new_login_token, new_pkce_verifier};
use crate::store::{NodeRecord, Store};

/// Network Map 快照重发间隔。既是保活，也让对端看到迟注册的 Node；
/// 事件式推送（MapDelta）在 #6 实现。
const MAP_REFRESH: Duration = Duration::from_secs(30);

/// 交互式登录授予的 Node 有效期（FR-3：默认 90 天）。
pub const LOGIN_NODE_TTL_SECS: i64 = 90 * 86_400;

pub struct ServeConfig {
    pub pool: SqlitePool,
    pub addr: AddressConfig,
    pub listen: SocketAddr,
    pub tls: Option<ServerTlsConfig>,
    pub map_refresh: Duration,
    /// 登录回调所在的 HTTP 面监听地址；配置了 OIDC 才有意义。
    pub http_listen: Option<SocketAddr>,
    pub oidc: Option<OidcConfig>,
    /// 一次性登录链接的有效期（默认 5 分钟）。
    pub login_ttl: Duration,
    /// 交互式登录授予的 Node 有效期（默认 90 天）。
    pub login_node_ttl_secs: i64,
}

impl ServeConfig {
    pub fn new(pool: SqlitePool, listen: SocketAddr) -> Self {
        Self {
            pool,
            addr: AddressConfig::default(),
            listen,
            tls: None,
            map_refresh: MAP_REFRESH,
            http_listen: None,
            oidc: None,
            login_ttl: LOGIN_TTL,
            login_node_ttl_secs: LOGIN_NODE_TTL_SECS,
        }
    }
}

pub struct ServeHandle {
    pub local_addr: SocketAddr,
    pub http_addr: Option<SocketAddr>,
    shutdown: tokio::sync::watch::Sender<bool>,
    http: Option<HttpHandle>,
    join: tokio::task::JoinHandle<()>,
}

impl ServeHandle {
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        if let Some(http) = &self.http {
            http.shutdown();
        }
    }

    pub async fn terminated(self) {
        let _ = self.join.await;
        if let Some(http) = self.http {
            let _ = http.terminated().await;
        }
    }
}

pub async fn serve(config: ServeConfig) -> anyhow::Result<ServeHandle> {
    let map_refresh = config.map_refresh;
    let store = Store::from_pool(config.pool, config.addr).await?;

    let (logins, http_handle) = match (config.oidc, config.http_listen) {
        (Some(oidc_config), Some(http_listen)) => {
            let oidc = OidcClient::discover(oidc_config).await?;
            let logins = Arc::new(LoginRegistry::new());
            let http_state = Arc::new(HttpState {
                oidc,
                logins: logins.clone(),
                store: store.clone(),
                login_node_ttl_secs: config.login_node_ttl_secs,
            });
            let http = serve_http(http_listen, http_state).await?;
            (logins, Some(http))
        }
        (Some(_), None) => anyhow::bail!("配置了 OIDC 但没有提供 --http-listen，回调无处落地"),
        _ => (Arc::new(LoginRegistry::new()), None),
    };

    let service = CoordServiceImpl {
        store,
        challenges: ChallengeCache::new(),
        map_refresh,
        logins,
        login_ttl: config.login_ttl,
        http_addr: http_handle.as_ref().map(|http| http.local_addr),
    };
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    let mut server = tonic::transport::Server::builder();
    if let Some(tls) = config.tls {
        server = server.tls_config(tls)?;
    }
    let router = server.add_service(CoordServer::new(service));
    let join = tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        tokio::select! {
            result = router.serve_with_incoming(incoming) => {
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
        http_addr: http_handle.as_ref().map(|http| http.local_addr),
        shutdown: shutdown_tx,
        http: http_handle,
        join,
    })
}

struct CoordServiceImpl {
    store: Store,
    challenges: ChallengeCache,
    map_refresh: Duration,
    logins: Arc<LoginRegistry>,
    login_ttl: Duration,
    http_addr: Option<SocketAddr>,
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
}

fn node_info_from(record: NodeRecord) -> NodeInfo {
    NodeInfo {
        node_id: record.id,
        name: record.name,
        ipv4: record.ipv4.to_string(),
        ipv6: record.ipv6.to_string(),
        tags: record.tags,
        owner_user: record.owner_user,
        expires_at_unix: record.expires_at_unix,
        node_key_pub: record.node_key_pub,
        endpoints: record.udp_endpoints,
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

        match self.logins.poll(&req.login_id, &machine_key_pub) {
            PollResult::Pending => Ok(Response::new(LoginStatusResponse {
                completed: false,
                node: None,
                error: None,
            })),
            PollResult::Completed(record) => {
                tracing::info!(node_id = %record.id, "interactive login delivered to node");
                Ok(Response::new(LoginStatusResponse {
                    completed: true,
                    node: Some(node_info_from(record)),
                    error: None,
                }))
            }
            PollResult::Failed(reason) => Ok(Response::new(LoginStatusResponse {
                completed: true,
                node: None,
                error: Some(reason),
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
            self.store
                .update_udp_endpoints(&record.id, &endpoints)
                .await
                .map_err(|e| {
                    tracing::error!(%e, "update udp endpoints failed");
                    Status::internal("更新 Endpoint 失败")
                })?;
            tracing::info!(node_id = %record.id, ?endpoints, "node endpoints updated");
        }

        // 打开发一份全量快照，然后周期性重发快照兼作保活；流保持打开。
        // 接收端断开时 send 失败，任务随之结束。
        let (tx, rx) = mpsc::channel(4);
        let store = self.store.clone();
        let refresh = self.map_refresh;
        tokio::spawn(async move {
            loop {
                let nodes = match store.network_map().await {
                    Ok(nodes) => nodes,
                    Err(error) => {
                        tracing::error!(%error, "build network map failed");
                        break;
                    }
                };
                let message = NetworkMapMessage {
                    kind: Some(hz_proto::network_map_message::Kind::Full(
                        hz_proto::NetworkMap {
                            nodes: nodes.into_iter().map(node_info_from).collect(),
                        },
                    )),
                };
                if tx.send(Ok(message)).await.is_err() {
                    tracing::debug!("map stream receiver dropped");
                    break;
                }
                tokio::time::sleep(refresh).await;
            }
        });
        tracing::info!(node_id = %record.id, "network map stream opened");
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
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
}
