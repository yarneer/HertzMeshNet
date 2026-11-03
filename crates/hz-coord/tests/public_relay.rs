//! #97 Seam B：coord 配置 / 未配置 `--public-relay-addr` /
//! `--public-stun-addr` 时，注册响应与 Network Map 全量快照是否携带地址
//! （真实 tonic over loopback + 内存 SQLite）。未配置时不携带——旧 coord
//! （N-2）对 Node 即此形态；Node 侧的三级优先级取值见 hz-engine 单测。

use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, ServeHandle, serve};
use hz_coord::store::Store;
use hz_proto::coord_client::CoordClient;
use hz_proto::network_map_message::Kind;
use hz_proto::{HelloRequest, PROTOCOL_VERSION, RegisterAuthKeyRequest, StreamMapRequest};
use rand_core::OsRng;
use tonic::transport::Channel;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

const LONG: Duration = Duration::from_secs(3600);

async fn start_server(
    public_relay: Option<&str>,
    public_stun: &[&str],
) -> (ServeHandle, Store, SocketAddr, String) {
    let store = Store::open_in_memory(AddressConfig::default())
        .await
        .unwrap();
    let mut config = ServeConfig::new(store.clone(), "127.0.0.1:0".parse().unwrap());
    config.map_keepalive = LONG;
    config.map_sweep = LONG;
    config.public_relay_addr = public_relay.map(str::to_string);
    config.public_stun_addrs = public_stun.iter().map(|s| s.to_string()).collect();
    let handle = serve(config).await.unwrap();
    let addr = handle.local_addr;
    let auth_key = store
        .create_auth_key(
            chrono::Utc::now().timestamp() + 3600,
            false,
            &["ci".to_string()],
        )
        .await
        .unwrap();
    (handle, store, addr, auth_key)
}

struct NodeKeys {
    machine: SigningKey,
    node_public: [u8; 32],
}

fn node_keys() -> NodeKeys {
    let secret = XStaticSecret::random_from_rng(OsRng);
    NodeKeys {
        machine: SigningKey::generate(&mut OsRng),
        node_public: XPublicKey::from(&secret).to_bytes(),
    }
}

async fn connect(addr: SocketAddr) -> CoordClient<Channel> {
    let channel = Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    CoordClient::new(channel)
}

async fn signed_challenge(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    hostname: &str,
) -> (Vec<u8>, Vec<u8>) {
    let hello = client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: hostname.to_owned(),
            node_version: None,
            os: None,
            arch: None,
        })
        .await
        .unwrap()
        .into_inner();
    (
        hello.challenge_nonce.clone(),
        keys.machine
            .sign(&hello.challenge_nonce)
            .to_bytes()
            .to_vec(),
    )
}

/// 配置了公共地址：注册响应与 Network Map 全量都携带。
#[tokio::test]
async fn configured_relay_and_stun_ride_registration_and_map() {
    let (handle, _store, addr, auth_key) = start_server(
        Some("https://relay.example.com"),
        &["relay.example.com:3478", "stun2.example.com:3478"],
    )
    .await;
    let mut client = connect(addr).await;
    let keys = node_keys();

    let (nonce, signature) = signed_challenge(&mut client, &keys, "node-a").await;
    let reply = client
        .register_with_auth_key(RegisterAuthKeyRequest {
            invite_code: None,
            challenge_nonce: nonce,
            challenge_signature: signature,
            auth_key,
            node_key_pub: keys.node_public.to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        reply.relay_addr.as_deref(),
        Some("https://relay.example.com")
    );
    assert_eq!(
        reply.stun_addrs,
        vec![
            "relay.example.com:3478".to_string(),
            "stun2.example.com:3478".to_string()
        ]
    );

    // Network Map 全量快照同样携带。
    let (nonce, signature) = signed_challenge(&mut client, &keys, "node-a").await;
    let mut stream = client
        .stream_network_map(StreamMapRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "node-a".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            endpoints: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    let message = stream.message().await.unwrap().unwrap();
    match message.kind {
        Some(Kind::Full(map)) => {
            assert_eq!(map.relay_addr.as_deref(), Some("https://relay.example.com"));
            assert_eq!(map.stun_addrs.len(), 2);
        }
        other => panic!("首条消息应是全量快照：{other:?}"),
    }
    handle.shutdown();
    handle.terminated().await;
}

/// 未配置：字段一律缺省（proto3 optional 不设值、repeated 为空）——与
/// 旧 coord（N-2）完全一致，Node 侧不感知。
#[tokio::test]
async fn unconfigured_sends_nothing() {
    let (handle, _store, addr, auth_key) = start_server(None, &[]).await;
    let mut client = connect(addr).await;
    let keys = node_keys();

    let (nonce, signature) = signed_challenge(&mut client, &keys, "node-b").await;
    let reply = client
        .register_with_auth_key(RegisterAuthKeyRequest {
            invite_code: None,
            challenge_nonce: nonce,
            challenge_signature: signature,
            auth_key,
            node_key_pub: keys.node_public.to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.relay_addr, None);
    assert!(reply.stun_addrs.is_empty());

    let (nonce, signature) = signed_challenge(&mut client, &keys, "node-b").await;
    let mut stream = client
        .stream_network_map(StreamMapRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "node-b".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            endpoints: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    let message = stream.message().await.unwrap().unwrap();
    match message.kind {
        Some(Kind::Full(map)) => {
            assert_eq!(map.relay_addr, None);
            assert!(map.stun_addrs.is_empty());
        }
        other => panic!("首条消息应是全量快照：{other:?}"),
    }
    handle.shutdown();
    handle.terminated().await;
}
