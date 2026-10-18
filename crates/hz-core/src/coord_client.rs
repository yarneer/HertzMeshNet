//! Node 侧的 Coordination Server 客户端：Hello → Machine Key 签挑战 → 注册、
//! Network Map 订阅。

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use anyhow::{Context, anyhow};
use ed25519_dalek::Signer;
use hyper_util::rt::TokioIo;
use hz_proto::coord_client::CoordClient;
use hz_proto::{
    BeginLoginRequest, HelloRequest, LoginStatusRequest, PROTOCOL_VERSION, RegisterAuthKeyRequest,
    StreamMapRequest,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tonic::Streaming;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Uri};
use tower_service::Service;

use crate::keys::KeyStore;
use crate::status::RegisteredInfo;

/// 占位的默认服务地址；部署时用 HZD_COORD_ADDR 或 `hz up --coord` 覆盖。
pub const DEFAULT_COORD_ADDR: &str = "https://coord.hznet.internal:443";

/// 用 Auth Key 完成 Machine-Key 挑战注册，返回授予的身份。
pub async fn register_with_auth_key(
    state_dir: &Path,
    auth_key: &str,
    hostname: &str,
    coord_addr: &str,
) -> anyhow::Result<RegisteredInfo> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);

    let hello = client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: hostname.to_owned(),
        })
        .await
        .map_err(|status| anyhow!("注册失败：Coordination Server 拒绝了 Hello（{status}）"))?
        .into_inner();

    let nonce = hello.challenge_nonce.clone();
    let signature = keys.machine().sign(&nonce).to_bytes();

    let response = client
        .register_with_auth_key(RegisterAuthKeyRequest {
            challenge_nonce: nonce,
            challenge_signature: signature.to_vec(),
            auth_key: auth_key.to_owned(),
            node_key_pub: keys.node_public().to_vec(),
        })
        .await
        .map_err(|status| anyhow!("注册失败：{status}"))?
        .into_inner();

    let node = response
        .node
        .ok_or_else(|| anyhow!("注册失败：服务端未返回 Node 信息"))?;
    Ok(RegisteredInfo {
        node_id: node.node_id,
        name: node.name,
        ipv4: node.ipv4,
        ipv6: node.ipv6,
        tags: node.tags,
        owner_user: node.owner_user,
        expires_at_unix: node.expires_at_unix,
    })
}

/// 打开 Network Map 下发流。请求经同一 Hello → 签挑战认证，
/// 并把本机的 UDP Endpoint（"ip:port"）上报给服务端。
pub async fn open_network_map_stream(
    state_dir: &Path,
    endpoints: Vec<String>,
    coord_addr: &str,
) -> anyhow::Result<Streaming<hz_proto::NetworkMapMessage>> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);

    let hello = client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
        })
        .await
        .map_err(|status| anyhow!("Network Map 订阅失败：Hello 被拒绝（{status}）"))?
        .into_inner();

    let nonce = hello.challenge_nonce;
    let signature = keys.machine().sign(&nonce).to_bytes();
    let stream = client
        .stream_network_map(StreamMapRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature.to_vec(),
            endpoints,
        })
        .await
        .map_err(|status| anyhow!("Network Map 订阅失败：{status}"))?
        .into_inner();
    Ok(stream)
}

/// 交互式登录的第一步：申请一次性登录链接（FR-2）。Node 侧只拿到 URL 与
/// 过期时间，不接触任何 IdP 概念。
pub async fn begin_interactive_login(
    state_dir: &Path,
    hostname: &str,
    coord_addr: &str,
) -> anyhow::Result<StartedLogin> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);

    let hello = client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: hostname.to_owned(),
        })
        .await
        .map_err(|status| anyhow!("登录失败：Coordination Server 拒绝了 Hello（{status}）"))?
        .into_inner();

    let nonce = hello.challenge_nonce.clone();
    let signature = keys.machine().sign(&nonce).to_bytes();
    let response = client
        .begin_interactive_login(BeginLoginRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: hostname.to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature.to_vec(),
            node_key_pub: keys.node_public().to_vec(),
        })
        .await
        .map_err(|status| anyhow!("登录失败：{status}"))?
        .into_inner();
    let login_id = response
        .login_url
        .rsplit('/')
        .next()
        .map(str::to_owned)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| anyhow!("登录失败：服务端返回的登录链接缺少标识"))?;
    Ok(StartedLogin {
        login_url: response.login_url,
        login_id,
        expires_unix: response.expires_unix,
    })
}

pub struct StartedLogin {
    pub login_url: String,
    pub login_id: String,
    pub expires_unix: i64,
}

/// LoginStatus 轮询一次的结果。
pub enum LoginPoll {
    Pending,
    Completed(RegisteredInfo),
    Failed(String),
}

/// 轮询一次登录结果（FR-2）：浏览器完成登录后这里取回注册信息。
pub async fn poll_login_status(
    state_dir: &Path,
    hostname: &str,
    coord_addr: &str,
    login_id: &str,
) -> anyhow::Result<LoginPoll> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);

    let hello = client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: hostname.to_owned(),
        })
        .await
        .map_err(|status| anyhow!("登录状态查询失败：Hello 被拒绝（{status}）"))?
        .into_inner();
    let nonce = hello.challenge_nonce;
    let signature = keys.machine().sign(&nonce).to_bytes();
    let response = client
        .login_status(LoginStatusRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: hostname.to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature.to_vec(),
            login_id: login_id.to_owned(),
        })
        .await
        .map_err(|status| anyhow!("登录状态查询失败：{status}"))?
        .into_inner();
    if let Some(error) = response.error {
        return Ok(LoginPoll::Failed(error));
    }
    match (response.completed, response.node) {
        (true, Some(node)) => Ok(LoginPoll::Completed(RegisteredInfo {
            node_id: node.node_id,
            name: node.name,
            ipv4: node.ipv4,
            ipv6: node.ipv6,
            tags: node.tags,
            owner_user: node.owner_user,
            expires_at_unix: node.expires_at_unix,
        })),
        (true, None) => Ok(LoginPoll::Failed(
            "服务端返回了完成态但没有 Node 信息".to_string(),
        )),
        (false, _) => Ok(LoginPoll::Pending),
    }
}

async fn connect(coord_addr: &str) -> anyhow::Result<Channel> {
    connect_tls_channel(coord_addr, None).await
}

/// 面向 Node 侧长连接服务的 TLS 通道：https 走 TLS（ca_pem 为 Some 时信任
/// 该私有 CA），连接器把 socket 绑到物理出口网卡（FR-7 共存），并启用
/// HTTP/2 keepalive 维持 NAT 后的长连接。coord 与 relay 共用。
pub(crate) async fn connect_tls_channel(
    addr: &str,
    ca_pem: Option<&str>,
) -> anyhow::Result<Channel> {
    let uri: Uri = addr
        .parse()
        .with_context(|| format!("无效的服务地址：{addr}"))?;
    let endpoint = tonic::transport::Endpoint::from_shared(uri.to_string())
        .with_context(|| format!("无效的服务地址：{addr}"))?;
    let endpoint = endpoint
        .http2_keep_alive_interval(std::time::Duration::from_secs(20))
        .keep_alive_while_idle(true)
        .connect_timeout(std::time::Duration::from_secs(10));
    let endpoint = match uri.scheme_str() {
        Some("https") => {
            let mut tls = ClientTlsConfig::new();
            if let Some(pem) = ca_pem {
                tls = tls.ca_certificate(Certificate::from_pem(pem.as_bytes()));
            }
            endpoint.tls_config(tls)?
        }
        _ => endpoint,
    };
    // 自带连接器在 connect(2) 之前把 socket 绑到物理出口网卡（FR-7 共存）；
    // TLS 仍由 endpoint 的配置包裹（connect_with_connector 内部处理）。
    let channel = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        endpoint.connect_with_connector(PhysicalEgressConnector),
    )
    .await
    .map_err(|_| anyhow!("连接 {addr} 超时"))?
    .map_err(|error| anyhow!("连接 {addr} 失败：{error}"))?;
    Ok(channel)
}

/// 到 Coordination Server 的 TCP 连接器：socket2 建栈、绑定物理出口网卡、
/// 非阻塞连接后交给 tokio。
#[derive(Clone)]
struct PhysicalEgressConnector;

impl Service<Uri> for PhysicalEgressConnector {
    type Response = TokioIo<tokio::net::TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        Box::pin(async move {
            let stream = dial(&uri).await?;
            Ok(TokioIo::new(stream))
        })
    }
}

async fn dial(uri: &Uri) -> io::Result<tokio::net::TcpStream> {
    let host = uri
        .host()
        .ok_or_else(|| io::Error::other(format!("coord uri 缺少主机名：{uri}")))?;
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    let mut last_error = io::Error::other(format!("{host}:{port} 未解析出可用地址"));
    for addr in addrs {
        match connect_bound(addr).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

/// 非阻塞 TCP 连接：SO_BINDTODEVICE 只约束发送路径，必须抢在 SYN 发出前生效，
/// 所以先绑物理出口网卡再 connect(2)。目标是 loopback 时不绑（本地测试服务
/// 无法从物理网卡到达）。
async fn connect_bound(addr: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if !addr.ip().is_loopback() {
        crate::netif::bind_to_physical_egress(&socket);
    }
    socket.set_nonblocking(true)?;
    match socket.connect(&SockAddr::from(addr)) {
        Ok(()) => {}
        // 非阻塞 connect(2) 立即返回 EINPROGRESS（std 未把它归入 WouldBlock，
        // 须按原始错误码识别）；立即连上的情况（本地回环）为 Ok。
        Err(error) if in_progress(&error) => {}
        Err(error) => return Err(error),
    }
    let stream = tokio::net::TcpStream::from_std(socket.into())?;
    stream.writable().await?;
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    Ok(stream)
}

/// 非阻塞 connect(2) 的"进行中"判定。
fn in_progress(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(libc::EINPROGRESS)
}

/// 本机主机名（供注册用）；取不到时退化为 "localhost"。
pub fn local_hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .unwrap_or_else(|| "localhost".to_string())
}
