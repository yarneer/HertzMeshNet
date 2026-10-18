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
use hz_proto::{HelloRequest, PROTOCOL_VERSION, RegisterAuthKeyRequest, StreamMapRequest};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tonic::Streaming;
use tonic::transport::{Channel, ClientTlsConfig, Uri};
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

async fn connect(coord_addr: &str) -> anyhow::Result<Channel> {
    let uri: Uri = coord_addr
        .parse()
        .with_context(|| format!("无效的 Coordination Server 地址：{coord_addr}"))?;
    let endpoint = tonic::transport::Endpoint::from_shared(uri.to_string())
        .with_context(|| format!("无效的 Coordination Server 地址：{coord_addr}"))?;
    let endpoint = match uri.scheme_str() {
        Some("https") => endpoint.tls_config(ClientTlsConfig::new())?,
        _ => endpoint,
    };
    // 自带连接器在 connect(2) 之前把 socket 绑到物理出口网卡（FR-7 共存）；
    // TLS 仍由 endpoint 的配置包裹（connect_with_connector 内部处理）。
    let channel = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        endpoint.connect_with_connector(PhysicalEgressConnector),
    )
    .await
    .map_err(|_| anyhow!("连接 {coord_addr} 超时"))?
    .map_err(|error| anyhow!("连接 {coord_addr} 失败：{error}"))?;
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
