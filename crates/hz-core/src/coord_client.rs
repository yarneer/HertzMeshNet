//! Node 侧的 Coordination Server 客户端：Hello → Machine Key 签挑战 → 注册。

use std::path::Path;

use anyhow::{Context, anyhow};
use ed25519_dalek::Signer;
use hz_proto::coord_client::CoordClient;
use hz_proto::{HelloRequest, PROTOCOL_VERSION, RegisterAuthKeyRequest};
use tonic::transport::{Channel, ClientTlsConfig};

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

async fn connect(coord_addr: &str) -> anyhow::Result<Channel> {
    let uri: tonic::transport::Uri = coord_addr
        .parse()
        .with_context(|| format!("无效的 Coordination Server 地址：{coord_addr}"))?;
    let endpoint = tonic::transport::Endpoint::from_shared(uri.to_string())
        .with_context(|| format!("无效的 Coordination Server 地址：{coord_addr}"))?;
    let endpoint = match uri.scheme_str() {
        Some("https") => endpoint.tls_config(ClientTlsConfig::new())?,
        _ => endpoint,
    };
    let channel = tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.connect())
        .await
        .map_err(|_| anyhow!("连接 {coord_addr} 超时"))?
        .map_err(|error| anyhow!("连接 {coord_addr} 失败：{error}"))?;
    Ok(channel)
}

/// 本机主机名（供注册用）；取不到时退化为 "localhost"。
pub fn local_hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|name| name.into_string().ok())
        .unwrap_or_else(|| "localhost".to_string())
}
