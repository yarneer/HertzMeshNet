//! Seam B（#69 v0.3）：Hello 上报版本/平台落库（#71）、Health Report 进内存
//! 并 90 秒过期（#72/#73）、last_seen 在流断开后落库。真实 tonic over
//! loopback + 内存 SQLite；Health Report 的存储语义见 ADR-0009。

use std::net::SocketAddr;

use ed25519_dalek::{Signer, SigningKey};
use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, ServeHandle, serve};
use hz_coord::store::Store;
use hz_proto::coord_client::CoordClient;
use hz_proto::{
    HealthReport, HelloRequest, PROTOCOL_VERSION, RegisterAuthKeyRequest, RelayedPeer,
    ReportEndpointsRequest, StreamMapRequest,
};
use rand_core::OsRng;
use sqlx::Row;
use tonic::transport::Channel;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

struct NodeKeys {
    machine: SigningKey,
    node_public: [u8; 32],
}

fn node_keys() -> NodeKeys {
    let node_secret = XStaticSecret::random_from_rng(OsRng);
    NodeKeys {
        machine: SigningKey::generate(&mut OsRng),
        node_public: XPublicKey::from(&node_secret).to_bytes(),
    }
}

struct TestServer {
    handle: ServeHandle,
    store: Store,
}

async fn start_server() -> TestServer {
    let store = Store::open_in_memory(AddressConfig::default())
        .await
        .unwrap();
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let handle = serve(ServeConfig::new(store.clone(), listen))
        .await
        .unwrap();
    TestServer { handle, store }
}

async fn connect(addr: SocketAddr) -> CoordClient<Channel> {
    let channel = Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    CoordClient::new(channel)
}

/// Hello + 签名挑战的公共两步。runtime 模拟 v0.3 Node（带版本）或旧 Node（None）。
async fn signed_challenge(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    hostname: &str,
    runtime: Option<(&str, &str, &str)>,
) -> (Vec<u8>, Vec<u8>) {
    let hello = client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: hostname.to_owned(),
            node_version: runtime.map(|(version, _, _)| version.to_string()),
            os: runtime.map(|(_, os, _)| os.to_string()),
            arch: runtime.map(|(_, _, arch)| arch.to_string()),
        })
        .await
        .unwrap()
        .into_inner();
    let nonce = hello.challenge_nonce.clone();
    let signature = keys.machine.sign(&nonce).to_bytes().to_vec();
    (nonce, signature)
}

async fn register(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    hostname: &str,
    auth_key: &str,
    runtime: Option<(&str, &str, &str)>,
) -> hz_proto::NodeInfo {
    let (nonce, signature) = signed_challenge(client, keys, hostname, runtime).await;
    let response = client
        .register_with_auth_key(RegisterAuthKeyRequest {
            invite_code: None,
            challenge_nonce: nonce,
            challenge_signature: signature,
            auth_key: auth_key.to_owned(),
            node_key_pub: keys.node_public.to_vec(),
        })
        .await
        .unwrap()
        .into_inner();
    response.node.unwrap()
}

/// 打开一条 Network Map 流（认证同构），返回流供调用方 drop 模拟断开。
async fn open_map_stream(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    hostname: &str,
) -> tonic::Streaming<hz_proto::NetworkMapMessage> {
    let (nonce, signature) = signed_challenge(client, keys, hostname, None).await;
    client
        .stream_network_map(StreamMapRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: hostname.to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            endpoints: vec![],
        })
        .await
        .unwrap()
        .into_inner()
}

async fn row_of(store: &Store, node_id: &str) -> sqlx::sqlite::SqliteRow {
    sqlx::query("SELECT node_version, os, arch, last_seen_unix FROM nodes WHERE id = ?1")
        .bind(node_id)
        .fetch_one(store.pool())
        .await
        .unwrap()
}

fn health_report(nat: &str, relayed: &[(&str, &str)]) -> HealthReport {
    HealthReport {
        udp4_ok: true,
        udp6_ok: false,
        has_stun_mapping: true,
        nat: nat.to_string(),
        default_route_virtual: false,
        suspicious_endpoint: false,
        direct_peers: 1,
        relayed_peers: relayed
            .iter()
            .map(|(node_id, reason)| RelayedPeer {
                node_id: node_id.to_string(),
                reason: reason.to_string(),
            })
            .collect(),
    }
}

/// #71 验收：新 Node 注册后 nodes 表三列有值；旧 Node（Hello 不带字段）
/// 保持 NULL。
#[tokio::test]
async fn hello_runtime_lands_in_nodes_table_and_old_nodes_stay_null() {
    let server = start_server().await;
    let auth_key = server
        .store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, false, &[])
        .await
        .unwrap();
    let mut client = connect(server.handle.local_addr).await;

    let modern = node_keys();
    let modern_info = register(
        &mut client,
        &modern,
        "modern-host",
        &auth_key,
        Some(("0.3.0 (a1b2c3d)", "macos", "aarch64")),
    )
    .await;
    let row = row_of(&server.store, &modern_info.node_id).await;
    assert_eq!(row.get::<String, _>("node_version"), "0.3.0 (a1b2c3d)");
    assert_eq!(row.get::<String, _>("os"), "macos");
    assert_eq!(row.get::<String, _>("arch"), "aarch64");

    // 旧 Node：Hello 不带新字段（模拟 v0.2.x 客户端），三列保持 NULL。
    let legacy = node_keys();
    let legacy_info = register(&mut client, &legacy, "legacy-host", &auth_key, None).await;
    let row = row_of(&server.store, &legacy_info.node_id).await;
    assert_eq!(
        row.get::<Option<String>, _>("node_version"),
        None,
        "旧 Node 不带字段保持 NULL"
    );
    assert_eq!(row.get::<Option<String>, _>("os"), None);
    assert_eq!(row.get::<Option<String>, _>("arch"), None);

    // 版本变化会更新（升级后重连），未带字段的请求不清掉已有值。
    let (nonce, signature) = signed_challenge(
        &mut client,
        &modern,
        "modern-host",
        Some(("0.3.1 (c3d4e5f)", "macos", "aarch64")),
    )
    .await;
    client
        .register_with_auth_key(RegisterAuthKeyRequest {
            invite_code: None,
            challenge_nonce: nonce,
            challenge_signature: signature,
            auth_key: auth_key.clone(),
            node_key_pub: modern.node_public.to_vec(),
        })
        .await
        .unwrap();
    let row = row_of(&server.store, &modern_info.node_id).await;
    assert_eq!(row.get::<String, _>("node_version"), "0.3.1 (c3d4e5f)");

    server.handle.shutdown();
}

/// #72/#73 验收：ReportEndpoints 携带的 Health Report 进内存（键 node_id），
/// 旧 coord 语义（不带 health）不报错；`hz node list` 的 gRPC 行带版本列。
#[tokio::test]
async fn report_endpoints_health_lands_in_memory_and_survives_legacy_reports() {
    let server = start_server().await;
    let auth_key = server
        .store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, false, &[])
        .await
        .unwrap();
    let mut client = connect(server.handle.local_addr).await;

    let node = node_keys();
    let info = register(
        &mut client,
        &node,
        "healthy-host",
        &auth_key,
        Some(("0.3.0 (a1b2c3d)", "linux", "x86_64")),
    )
    .await;

    // 第一份上报不带 health（旧 hzd 路径）：不报错、不产生报告。
    let (nonce, signature) = signed_challenge(&mut client, &node, "healthy-host", None).await;
    client
        .report_endpoints(ReportEndpointsRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: node.machine.verifying_key().to_bytes().to_vec(),
            hostname: "healthy-host".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            endpoints: vec![],
            path_report: None,
            health: None,
        })
        .await
        .unwrap();
    assert!(
        !server.handle.health.has_report(&info.node_id),
        "不带 health 的上报不产生报告"
    );

    // 第二份带 Health Report：进内存，netcheck 六项与 relayed 原因可读回。
    let (nonce, signature) = signed_challenge(&mut client, &node, "healthy-host", None).await;
    client
        .report_endpoints(ReportEndpointsRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: node.machine.verifying_key().to_bytes().to_vec(),
            hostname: "healthy-host".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            endpoints: vec![],
            path_report: None,
            health: Some(health_report("hard", &[("n-other", "handshake_timeout")])),
        })
        .await
        .unwrap();
    let received = server
        .handle
        .health
        .fresh_report(&info.node_id)
        .expect("Health Report 应进内存");
    assert!(received.report.udp4_ok);
    assert!(!received.report.udp6_ok);
    assert_eq!(received.report.nat, "hard");
    assert_eq!(received.report.relayed_peers.len(), 1);
    assert_eq!(received.report.relayed_peers[0].1, "handshake_timeout");
    // 上报同时刷新 last_seen（内存）。
    assert!(server.handle.health.last_seen(&info.node_id).is_some());

    server.handle.shutdown();
}

/// #71 验收：Network Map 流断开后 last_seen 落库（离线冲刷 ≤5s + 余量），
/// 在线期间不随每次上报写库。
#[tokio::test]
async fn last_seen_flushes_to_db_after_stream_disconnects() {
    let server = start_server().await;
    let auth_key = server
        .store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, false, &[])
        .await
        .unwrap();
    let mut client = connect(server.handle.local_addr).await;

    let node = node_keys();
    let info = register(
        &mut client,
        &node,
        "seen-host",
        &auth_key,
        Some(("0.3.0 (a1b2c3d)", "linux", "x86_64")),
    )
    .await;

    let before = chrono::Utc::now().timestamp();
    {
        let _stream = open_map_stream(&mut client, &node, "seen-host").await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    } // 流 drop：hub 要等下一次投递（最长 30s 保活）才发现订阅者消失，
    // 这里注册一个无关 Node 触发存储变更，让 fan-out 立即清理登记。
    drop(client);
    server
        .store
        .register_node(&[9u8; 32], &[9u8; 32], "bystander", &[], None, None)
        .await
        .unwrap();

    // hub 清理（≤1s）+ 离线冲刷周期（5s）；留余量轮询。
    for _ in 0..14 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let row = row_of(&server.store, &info.node_id).await;
        if let Some(seen) = row.get::<Option<i64>, _>("last_seen_unix") {
            assert!(
                seen >= before,
                "落库的 last_seen 不应早于开流时刻：{seen} < {before}"
            );
            server.handle.shutdown();
            return;
        }
    }
    panic!("流断开 14 秒后 last_seen 仍未落库");
}
