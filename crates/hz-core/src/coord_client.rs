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
    AdminCreateAuthKeyRequest, AdminCreateInviteRequest, AdminListInvitesRequest,
    AdminRevokeAuthKeyRequest, AdminRevokeInviteRequest, BeginLoginRequest, DeleteNodeRequest,
    HelloRequest, ListNodesRequest, LoginStatusRequest, PROTOCOL_VERSION, PolicyGetRequest,
    PolicyPushRequest, PolicyRollbackRequest, RegisterAuthKeyRequest, RenameNodeRequest,
    ReportEndpointsRequest, RevokeNodeRequest, StreamMapRequest,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tonic::Streaming;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Uri};
use tower_service::Service;

use crate::endpoint::{DiscoveredEndpoint, EndpointKind};
use crate::keys::KeyStore;
use crate::status::RegisteredInfo;

/// 占位的默认服务地址；部署时用 HZD_COORD_ADDR 或 `hz up --coord` 覆盖。
pub const DEFAULT_COORD_ADDR: &str = "https://coord.hznet.internal:443";

/// 用 Auth Key 完成 Machine-Key 挑战注册，返回授予的身份。
pub async fn register_with_auth_key(
    state_dir: &Path,
    auth_key: &str,
    invite_code: Option<&str>,
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
            invite_code: invite_code.map(str::to_string),
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
        network_cidr: response.network_cidr,
        dns_v4: response.dns_v4,
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

/// 一次 Endpoint 上报附带的路径管理累计计数（FR-12 打洞成功率的数据源）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PunchCounters {
    pub attempts: u64,
    pub successes: u64,
}

/// 上报收集到的 Endpoint（FR-8）：Hello → 签挑战 → ReportEndpoints。
/// 服务端落库后随 Network Map 差量推给其他 Node。punch 为 Some 时随上报
/// 携带打洞累计计数（Node 自启动起），服务端按 Node 去差量累加。
pub async fn report_endpoints(
    state_dir: &Path,
    endpoints: &[DiscoveredEndpoint],
    coord_addr: &str,
    punch: Option<PunchCounters>,
) -> anyhow::Result<()> {
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
        .map_err(|status| anyhow!("Endpoint 上报失败：Hello 被拒绝（{status}）"))?
        .into_inner();
    let nonce = hello.challenge_nonce;
    let signature = keys.machine().sign(&nonce).to_bytes();
    client
        .report_endpoints(ReportEndpointsRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature.to_vec(),
            endpoints: endpoints
                .iter()
                .map(|endpoint| hz_proto::Endpoint {
                    addr: endpoint.addr.ip().to_string(),
                    port: endpoint.addr.port() as u32,
                    kind: match endpoint.kind {
                        EndpointKind::Lan => hz_proto::EndpointKind::Lan as i32,
                        EndpointKind::Stun => hz_proto::EndpointKind::Stun as i32,
                        EndpointKind::V6 => hz_proto::EndpointKind::V6 as i32,
                    },
                })
                .collect(),
            path_report: punch.map(|counters| hz_proto::PathReport {
                punch_attempts: u32::try_from(counters.attempts).unwrap_or(u32::MAX),
                punch_success: u32::try_from(counters.successes).unwrap_or(u32::MAX),
            }),
        })
        .await
        .map_err(|status| anyhow!("Endpoint 上报失败：{status}"))?;
    Ok(())
}

/// 交互式登录的第一步：申请一次性登录链接（FR-2）。Node 侧只拿到 URL 与
/// 过期时间，不接触任何 IdP 概念。node_key_pub 由调用方决定：已注册的 Node
/// 重新登录时应传入轮换后的新公钥，首次登录传当前公钥。
pub async fn begin_interactive_login(
    state_dir: &Path,
    hostname: &str,
    coord_addr: &str,
    node_key_pub: [u8; 32],
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
            node_key_pub: node_key_pub.to_vec(),
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
            network_cidr: response.network_cidr,
            dns_v4: response.dns_v4,
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

/// Hello → 签挑战的公共两步；返回（nonce, signature）。
async fn signed_challenge(
    client: &mut CoordClient<Channel>,
    keys: &crate::keys::KeyStore,
    hostname: &str,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let hello = client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: hostname.to_owned(),
        })
        .await
        .map_err(|status| anyhow!("Hello 被拒绝（{status}）"))?
        .into_inner();
    let nonce = hello.challenge_nonce;
    let signature = keys.machine().sign(&nonce).to_bytes().to_vec();
    Ok((nonce, signature))
}

/// `hz policy get` 取回的当前 Policy 与历史。
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    /// 当前版本号；尚无 Policy 时为 0。
    pub version: i64,
    /// 当前 Policy 的 TOML 原文；尚无 Policy 时为 None。
    pub content: Option<String>,
    pub history: Vec<PolicyVersionEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVersionEntry {
    pub version: i64,
    pub created_at_unix: i64,
}

/// Policy 整份替换（FR-10）。返回服务端分配的版本号。
pub async fn policy_push(state_dir: &Path, coord_addr: &str, content: &str) -> anyhow::Result<i64> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);
    let (nonce, signature) = signed_challenge(&mut client, &keys, &local_hostname()).await?;
    let response = client
        .policy_push(PolicyPushRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            content: content.to_owned(),
        })
        .await
        .map_err(|status| anyhow!("Policy 推送被拒绝（{status}）"))?
        .into_inner();
    Ok(response.version)
}

/// 查看当前 Policy 与历史版本（FR-10）。
pub async fn policy_get(state_dir: &Path, coord_addr: &str) -> anyhow::Result<PolicySnapshot> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);
    let (nonce, signature) = signed_challenge(&mut client, &keys, &local_hostname()).await?;
    let response = client
        .policy_get(PolicyGetRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature,
        })
        .await
        .map_err(|status| anyhow!("Policy 查询失败（{status}）"))?
        .into_inner();
    Ok(PolicySnapshot {
        version: response.version,
        content: response.content,
        history: response
            .history
            .into_iter()
            .map(|entry| PolicyVersionEntry {
                version: entry.version,
                created_at_unix: entry.created_at_unix,
            })
            .collect(),
    })
}

/// 回滚到指定历史版本（FR-10）。引用已失效的版本会被服务端拒绝。
pub async fn policy_rollback(
    state_dir: &Path,
    coord_addr: &str,
    version: i64,
) -> anyhow::Result<i64> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);
    let (nonce, signature) = signed_challenge(&mut client, &keys, &local_hostname()).await?;
    let response = client
        .policy_rollback(PolicyRollbackRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            version,
        })
        .await
        .map_err(|status| anyhow!("Policy 回滚被拒绝（{status}）"))?
        .into_inner();
    Ok(response.version)
}

// ---- Admin 远程管理（FR-11 / #12）：与 Policy 同一挑战认证形态。----

/// 签发出的 Auth Key：明文只在内存/调用方输出里出现一次。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedAuthKey {
    pub plaintext: String,
    pub key_id: String,
}

pub struct IssuedInvite {
    pub invite_code: String,
}

pub struct InviteSummary {
    pub invite_id: String,
    pub expires_at_unix: i64,
    pub max_uses: i64,
    pub use_count: i64,
    pub tags: Vec<String>,
    pub owner_name: Option<String>,
    pub revoked: bool,
}

/// 管理列表的一行（服务端 AdminNodeInfo 的对应物）。
/// Serialize 供 hzd 原样透传给 `hz node list --json`。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ManagedNode {
    pub node_id: String,
    pub name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub tags: Vec<String>,
    pub owner_user: Option<String>,
    pub expires_at_unix: Option<i64>,
    pub revoked: bool,
}

/// 签发 Auth Key（仅 Admin）。
pub async fn admin_create_auth_key(
    state_dir: &Path,
    coord_addr: &str,
    expires_unix: i64,
    single_use: bool,
    tags: &[String],
) -> anyhow::Result<IssuedAuthKey> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);
    let (nonce, signature) = signed_challenge(&mut client, &keys, &local_hostname()).await?;
    let response = client
        .admin_create_auth_key(AdminCreateAuthKeyRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            expires_unix,
            single_use,
            tags: tags.to_vec(),
        })
        .await
        .map_err(|status| anyhow!("Auth Key 签发被拒绝（{status}）"))?
        .into_inner();
    Ok(IssuedAuthKey {
        plaintext: response.auth_key,
        key_id: response.key_id,
    })
}

/// 吊销 Auth Key（仅 Admin）。
pub async fn admin_create_invite(
    state_dir: &Path,
    coord_addr: &str,
    ttl_secs: i64,
    max_uses: i64,
    tags: &[String],
    owner_name: Option<String>,
    node_ttl_days: Option<i64>,
) -> anyhow::Result<IssuedInvite> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);
    let (nonce, signature) = signed_challenge(&mut client, &keys, &local_hostname()).await?;
    let response = client
        .admin_create_invite(AdminCreateInviteRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            ttl_secs,
            max_uses,
            tags: tags.to_vec(),
            owner_name,
            node_ttl_days,
        })
        .await?;
    Ok(IssuedInvite {
        invite_code: response.into_inner().invite_code,
    })
}

pub async fn admin_list_invites(
    state_dir: &Path,
    coord_addr: &str,
) -> anyhow::Result<Vec<InviteSummary>> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);
    let (nonce, signature) = signed_challenge(&mut client, &keys, &local_hostname()).await?;
    let response = client
        .admin_list_invites(AdminListInvitesRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature,
        })
        .await?;
    Ok(response
        .into_inner()
        .invites
        .into_iter()
        .map(|info| InviteSummary {
            invite_id: info.invite_id,
            expires_at_unix: info.expires_at_unix,
            max_uses: info.max_uses,
            use_count: info.use_count,
            tags: info.tags,
            owner_name: info.owner_name,
            revoked: info.revoked_at_unix.is_some(),
        })
        .collect())
}

pub async fn admin_revoke_invite(
    state_dir: &Path,
    coord_addr: &str,
    invite_id: &str,
) -> anyhow::Result<()> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);
    let (nonce, signature) = signed_challenge(&mut client, &keys, &local_hostname()).await?;
    client
        .admin_revoke_invite(AdminRevokeInviteRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            invite_id: invite_id.to_owned(),
        })
        .await?;
    Ok(())
}

pub async fn admin_revoke_auth_key(
    state_dir: &Path,
    coord_addr: &str,
    key_id: &str,
) -> anyhow::Result<()> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);
    let (nonce, signature) = signed_challenge(&mut client, &keys, &local_hostname()).await?;
    client
        .admin_revoke_auth_key(AdminRevokeAuthKeyRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            key_id: key_id.to_owned(),
        })
        .await
        .map_err(|status| anyhow!("Auth Key 吊销被拒绝（{status}）"))?;
    Ok(())
}

/// 列出 Node：Admin 得到全部（含已吊销），普通 User 得到自己名下。
pub async fn list_nodes(state_dir: &Path, coord_addr: &str) -> anyhow::Result<Vec<ManagedNode>> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);
    let (nonce, signature) = signed_challenge(&mut client, &keys, &local_hostname()).await?;
    let response = client
        .list_nodes(ListNodesRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature,
        })
        .await
        .map_err(|status| anyhow!("列出 Node 被拒绝（{status}）"))?
        .into_inner();
    Ok(response
        .nodes
        .into_iter()
        .map(|node| ManagedNode {
            node_id: node.node_id,
            name: node.name,
            ipv4: node.ipv4,
            ipv6: node.ipv6,
            tags: node.tags,
            owner_user: node.owner_user,
            expires_at_unix: node.expires_at_unix,
            revoked: node.revoked,
        })
        .collect())
}

/// 改名（Admin 任意；普通 User 仅自己名下）。返回服务端规范化后的新名。
pub async fn rename_node(
    state_dir: &Path,
    coord_addr: &str,
    node_id: &str,
    new_name: &str,
) -> anyhow::Result<String> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);
    let (nonce, signature) = signed_challenge(&mut client, &keys, &local_hostname()).await?;
    let response = client
        .rename_node(RenameNodeRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            node_id: node_id.to_owned(),
            new_name: new_name.to_owned(),
        })
        .await
        .map_err(|status| anyhow!("Node 改名被拒绝（{status}）"))?
        .into_inner();
    Ok(response.name)
}

/// 删除 Node（硬删，Admin 任意；普通 User 仅自己名下）。
pub async fn delete_node(state_dir: &Path, coord_addr: &str, node_id: &str) -> anyhow::Result<()> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);
    let (nonce, signature) = signed_challenge(&mut client, &keys, &local_hostname()).await?;
    client
        .delete_node(DeleteNodeRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            node_id: node_id.to_owned(),
        })
        .await
        .map_err(|status| anyhow!("Node 删除被拒绝（{status}）"))?;
    Ok(())
}

/// 吊销 Node（仅 Admin）：保留审计行，立即从所有 Network Map 消失。
pub async fn revoke_node(state_dir: &Path, coord_addr: &str, node_id: &str) -> anyhow::Result<()> {
    let keys = KeyStore::load_or_create(state_dir)?;
    let channel = connect(coord_addr).await?;
    let mut client = CoordClient::new(channel);
    let (nonce, signature) = signed_challenge(&mut client, &keys, &local_hostname()).await?;
    client
        .revoke_node(RevokeNodeRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine_public().to_vec(),
            hostname: local_hostname(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            node_id: node_id.to_owned(),
        })
        .await
        .map_err(|status| anyhow!("Node 吊销被拒绝（{status}）"))?;
    Ok(())
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
            // 默认根不能留空：tonic 的 ClientTlsConfig 不自动加载任何系统/内置
            // CA（两个 with_*_roots 开关默认全关），公网 ACME 证书会被判
            // UnknownIssuer。ca_pem 显式给私有 CA 时以它为准。
            let mut tls = ClientTlsConfig::new().with_webpki_roots();
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
    // 经外层解析器：系统 DNS 被其他网络工具接管返回假地址时改问引导 DNS（#23）。
    let owned_host = host.to_string();
    let addrs: Vec<SocketAddr> =
        tokio::task::spawn_blocking(move || crate::outer_dns::global().resolve(&owned_host, port))
            .await
            .map_err(io::Error::other)??;
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
