//! gRPC 服务：挑战签发与校验、Auth Key 注册、协议版本闸门。
//! BeginInteractiveLogin 与 StreamNetworkMap 在本票据只定义接口（#10、#6 实现）。

use std::net::SocketAddr;
use std::pin::Pin;
use std::time::SystemTime;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hz_proto::MIN_SUPPORTED_PROTOCOL_VERSION;
use hz_proto::coord_server::{Coord, CoordServer};
use hz_proto::{
    BeginLoginRequest, BeginLoginResponse, HelloRequest, HelloResponse, NetworkMapMessage,
    NodeInfo, RegisterAuthKeyRequest, RegisterResponse, StreamMapRequest,
};
use sqlx::SqlitePool;
use tonic::transport::ServerTlsConfig;
use tonic::{Request, Response, Status};

use crate::addr::AddressConfig;
use crate::challenge::{CHALLENGE_TTL, ChallengeCache};
use crate::store::Store;

pub struct ServeConfig {
    pub pool: SqlitePool,
    pub addr: AddressConfig,
    pub listen: SocketAddr,
    pub tls: Option<ServerTlsConfig>,
}

impl ServeConfig {
    pub fn new(pool: SqlitePool, listen: SocketAddr) -> Self {
        Self {
            pool,
            addr: AddressConfig::default(),
            listen,
            tls: None,
        }
    }
}

pub struct ServeHandle {
    pub local_addr: SocketAddr,
    shutdown: tokio::sync::watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

impl ServeHandle {
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub async fn terminated(self) {
        let _ = self.join.await;
    }
}

pub async fn serve(config: ServeConfig) -> anyhow::Result<ServeHandle> {
    let store = Store::from_pool(config.pool, config.addr).await?;
    let service = CoordServiceImpl {
        store,
        challenges: ChallengeCache::new(),
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
        shutdown: shutdown_tx,
        join,
    })
}

struct CoordServiceImpl {
    store: Store,
    challenges: ChallengeCache,
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
            node: Some(NodeInfo {
                node_id: record.id,
                name: record.name,
                ipv4: record.ipv4.to_string(),
                ipv6: record.ipv6.to_string(),
                tags: record.tags,
                owner_user: record.owner_user,
                expires_at_unix: record.expires_at_unix,
            }),
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
        _request: Request<StreamMapRequest>,
    ) -> Result<Response<Self::StreamNetworkMapStream>, Status> {
        Err(Status::unimplemented("Network Map 下发尚未实现"))
    }
}

fn system_time_to_unix(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(i64::MAX)
}
