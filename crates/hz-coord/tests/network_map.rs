//! Network Map 下发的服务端契约（真实 tonic over loopback + 内存 SQLite）：
//! 挑战认证、Endpoint 落库、全量快照、增量推送（注册/Endpoint/吊销/到期清扫）、
//! 断线后重启再连收新全量。

use std::collections::HashSet;
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
use tonic::{Response, Status};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

const LONG: Duration = Duration::from_secs(3600);

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

fn config(store: &Store, keepalive: Duration, sweep: Duration) -> ServeConfig {
    let mut config = ServeConfig::new(store.clone(), "127.0.0.1:0".parse().unwrap());
    config.map_keepalive = keepalive;
    config.map_sweep = sweep;
    config
}

async fn start_server(keepalive: Duration, sweep: Duration) -> (ServeHandle, Store, SocketAddr) {
    let store = Store::open_in_memory(AddressConfig::default())
        .await
        .unwrap();
    let handle = serve(config(&store, keepalive, sweep)).await.unwrap();
    let addr = handle.local_addr;
    (handle, store, addr)
}

/// 服务停掉后在同一地址重启；TIME_WAIT 期内 bind 可能失败，重试几秒。
async fn restart_on_same_addr(
    store: &Store,
    addr: SocketAddr,
    keepalive: Duration,
    sweep: Duration,
) -> ServeHandle {
    for _ in 0..100 {
        let mut serve_config = config(store, keepalive, sweep);
        serve_config.listen = addr;
        if let Ok(handle) = serve(serve_config).await {
            return handle;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("无法在 {addr} 上重启 coord serve");
}

async fn connect(addr: SocketAddr) -> CoordClient<Channel> {
    let channel = Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    CoordClient::new(channel)
}

async fn register(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    hostname: &str,
    auth_key: &str,
) -> hz_proto::NodeInfo {
    let hello = client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: hostname.to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    let signature = keys.machine.sign(&hello.challenge_nonce);
    client
        .register_with_auth_key(RegisterAuthKeyRequest {
            challenge_nonce: hello.challenge_nonce,
            challenge_signature: signature.to_bytes().to_vec(),
            auth_key: auth_key.to_owned(),
            node_key_pub: keys.node_public.to_vec(),
        })
        .await
        .unwrap()
        .into_inner()
        .node
        .unwrap()
}

type MapStream = tonic::codec::Streaming<hz_proto::NetworkMapMessage>;

async fn open_map(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    endpoints: Vec<String>,
    signature_override: Option<[u8; 64]>,
) -> Result<MapStream, Status> {
    let hello = client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "map-client".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    let signature =
        signature_override.unwrap_or_else(|| keys.machine.sign(&hello.challenge_nonce).to_bytes());
    client
        .stream_network_map(StreamMapRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "map-client".to_owned(),
            challenge_nonce: hello.challenge_nonce,
            challenge_signature: signature.to_vec(),
            endpoints,
        })
        .await
        .map(Response::into_inner)
}

/// 限时等下一条消息；delta/keepalive 混流时按谓词过滤。
async fn next_message(stream: &mut MapStream, timeout: Duration) -> hz_proto::NetworkMapMessage {
    tokio::time::timeout(timeout, stream.message())
        .await
        .unwrap_or_else(|_| panic!("{timeout:?} 内未收到下一条 Map 消息"))
        .unwrap()
        .unwrap()
}

async fn next_delta(stream: &mut MapStream, timeout: Duration) -> hz_proto::MapDelta {
    loop {
        match next_message(stream, timeout).await.kind.unwrap() {
            Kind::Full(_) => continue,
            Kind::Delta(delta) => return delta,
        }
    }
}

async fn auth_key(store: &Store) -> String {
    store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, false, &[])
        .await
        .unwrap()
}

#[tokio::test]
async fn map_stream_authenticates_upserts_endpoints_and_delivers_full_snapshot() {
    let (handle, store, addr) = start_server(LONG, LONG).await;
    let auth_key = auth_key(&store).await;

    let node_a = node_keys();
    let node_b = node_keys();
    let mut client = connect(addr).await;
    let info_a = register(&mut client, &node_a, "node-a", &auth_key).await;
    let info_b = register(&mut client, &node_b, "node-b", &auth_key).await;

    let mut stream = open_map(
        &mut client,
        &node_a,
        vec!["192.168.1.5:51820".to_string()],
        None,
    )
    .await
    .unwrap();

    let message = next_message(&mut stream, Duration::from_secs(5)).await;
    let Kind::Full(map) = message.kind.unwrap() else {
        panic!("打开流后第一条必须是全量 Network Map");
    };
    let names: HashSet<String> = map.nodes.iter().map(|n| n.name.clone()).collect();
    assert_eq!(
        names,
        HashSet::from([info_a.name.clone(), info_b.name.clone()]),
        "快照必须包含全部未吊销、未过期的 Node"
    );
    for node in &map.nodes {
        assert_eq!(
            node.node_key_pub.len(),
            32,
            "快照必须携带数据面用的 Node Key 公钥"
        );
    }
    let reported = map
        .nodes
        .iter()
        .find(|n| n.node_id == info_a.node_id)
        .unwrap();
    assert_eq!(
        reported.endpoints,
        vec!["192.168.1.5:51820".to_string()],
        "打开流时上报的 Endpoint 必须回显在快照里"
    );

    let persisted = store
        .node_by_machine_key(&node_a.machine.verifying_key().to_bytes())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        persisted.udp_endpoints,
        vec!["192.168.1.5:51820".to_string()]
    );

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn map_stream_sends_empty_delta_as_keepalive() {
    let (handle, store, addr) = start_server(Duration::from_millis(200), LONG).await;
    let mut client = connect(addr).await;

    let node = node_keys();
    let auth_key = auth_key(&store).await;
    let _info = register(&mut client, &node, "keeper", &auth_key).await;

    let mut stream = open_map(&mut client, &node, vec![], None).await.unwrap();
    let first = next_message(&mut stream, Duration::from_secs(5)).await;
    assert!(matches!(first.kind, Some(Kind::Full(_))), "首条仍是全量");
    for expected in 1..=2 {
        let delta = next_delta(&mut stream, Duration::from_secs(5)).await;
        assert!(
            delta.added_or_updated.is_empty() && delta.removed_node_ids.is_empty(),
            "第 {expected} 份保活应是空差量：{delta:?}"
        );
    }

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn map_stream_rejects_bad_signature_and_unregistered_keys() {
    let (handle, store, addr) = start_server(LONG, LONG).await;
    let mut client = connect(addr).await;

    let stranger = node_keys();
    let status = open_map(&mut client, &stranger, vec![], None)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status}");

    let node = node_keys();
    let auth_key = auth_key(&store).await;
    let _info = register(&mut client, &node, "signed-node", &auth_key).await;
    let bad_signature = SigningKey::generate(&mut OsRng).sign(b"nonce").to_bytes();
    let status = open_map(&mut client, &node, vec![], Some(bad_signature))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated, "{status}");

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn new_node_registration_pushes_delta_and_lands_in_client_cache() {
    let (handle, store, addr) = start_server(LONG, LONG).await;
    let auth_key = auth_key(&store).await;
    let node_a = node_keys();
    let mut client = connect(addr).await;
    let info_a = register(&mut client, &node_a, "node-a", &auth_key).await;

    let mut stream = open_map(
        &mut client,
        &node_a,
        vec!["10.0.0.1:51820".to_string()],
        None,
    )
    .await
    .unwrap();
    let full = next_message(&mut stream, Duration::from_secs(5)).await;
    let Kind::Full(map) = full.kind.unwrap() else {
        panic!("首条必须是全量");
    };
    assert_eq!(
        map.nodes.len(),
        1,
        "A 单独在线时快照只有 A：{:?}",
        map.nodes
    );

    let node_b = node_keys();
    let info_b = register(&mut client, &node_b, "node-b", &auth_key).await;

    let delta = next_delta(&mut stream, Duration::from_secs(2)).await;
    let added_names: HashSet<String> = delta
        .added_or_updated
        .iter()
        .map(|n| n.name.clone())
        .collect();
    assert_eq!(
        added_names,
        HashSet::from(["node-b".to_string()]),
        "B 注册后 2 秒内应推来只含 B 的差量：{delta:?}"
    );
    assert!(delta.removed_node_ids.is_empty());
    let added_b = delta
        .added_or_updated
        .iter()
        .find(|n| n.node_id == info_b.node_id)
        .unwrap();
    assert_eq!(added_b.ipv4, info_b.ipv4);
    assert_eq!(added_b.node_key_pub.len(), 32);

    // 消息照 hzd 的方式喂进客户端缓存，从公共快照断言。
    let dir = tempfile::tempdir().unwrap();
    let cache = hz_core::map::NetworkMapCache::load(dir.path()).unwrap();
    cache.apply_full(map.nodes.into_iter().map(Into::into).collect());
    cache.apply_delta(
        delta.added_or_updated.into_iter().map(Into::into).collect(),
        delta.removed_node_ids,
    );
    let snapshot_names: HashSet<String> = cache.snapshot().iter().map(|n| n.name.clone()).collect();
    assert_eq!(
        snapshot_names,
        HashSet::from([info_a.name.clone(), info_b.name.clone(),]),
        "缓存快照必须同时含 A 与 B"
    );

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn revoked_node_is_pushed_as_removed_and_absent_from_new_full_maps() {
    let (handle, store, addr) = start_server(LONG, LONG).await;
    let auth_key = auth_key(&store).await;
    let node_a = node_keys();
    let node_b = node_keys();
    let mut client = connect(addr).await;
    let _info_a = register(&mut client, &node_a, "node-a", &auth_key).await;
    let info_b = register(&mut client, &node_b, "node-b", &auth_key).await;

    let mut stream = open_map(&mut client, &node_a, vec![], None).await.unwrap();
    let _ = next_message(&mut stream, Duration::from_secs(5)).await;

    assert!(store.revoke_node(&info_b.node_id).await.unwrap());
    assert!(
        !store.revoke_node(&info_b.node_id).await.unwrap(),
        "重复吊销是空操作"
    );

    let delta = next_delta(&mut stream, Duration::from_secs(2)).await;
    assert_eq!(
        delta.removed_node_ids,
        vec![info_b.node_id.clone()],
        "吊销后应推来 removed_node_ids=[B]：{delta:?}"
    );
    assert!(delta.added_or_updated.is_empty());

    let mut fresh = open_map(&mut client, &node_a, vec![], None).await.unwrap();
    let message = next_message(&mut fresh, Duration::from_secs(5)).await;
    let Kind::Full(map) = message.kind.unwrap() else {
        panic!("重连后首条必须是全量");
    };
    let names: HashSet<String> = map.nodes.iter().map(|n| n.name.clone()).collect();
    assert_eq!(
        names,
        HashSet::from(["node-a".to_string()]),
        "吊销后全量快照不得再含 B：{names:?}"
    );

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn expired_node_is_swept_out_of_the_map() {
    let (handle, store, addr) = start_server(LONG, Duration::from_millis(200)).await;
    let auth_key = auth_key(&store).await;
    let node_a = node_keys();
    let node_b = node_keys();
    let mut client = connect(addr).await;
    let _info_a = register(&mut client, &node_a, "node-a", &auth_key).await;
    let info_b = register(&mut client, &node_b, "node-b", &auth_key).await;

    let mut stream = open_map(&mut client, &node_a, vec![], None).await.unwrap();
    let _ = next_message(&mut stream, Duration::from_secs(5)).await;

    // 绕过 notify 的直写（模拟在线期间到期跨越）：只有周期清扫能接住。
    sqlx::query("UPDATE nodes SET expires_at_unix = ?1 WHERE id = ?2")
        .bind(hz_coord::store::unix_now() - 1)
        .bind(&info_b.node_id)
        .execute(store.pool())
        .await
        .unwrap();

    let delta = next_delta(&mut stream, Duration::from_secs(5)).await;
    assert_eq!(
        delta.removed_node_ids,
        vec![info_b.node_id.clone()],
        "到期被清扫后应推来 removed=[B]：{delta:?}"
    );

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn endpoint_change_is_pushed_as_delta() {
    let (handle, store, addr) = start_server(LONG, LONG).await;
    let auth_key = auth_key(&store).await;
    let node_a = node_keys();
    let node_b = node_keys();
    let mut client = connect(addr).await;
    let _info_a = register(&mut client, &node_a, "node-a", &auth_key).await;
    let info_b = register(&mut client, &node_b, "node-b", &auth_key).await;

    let mut stream = open_map(&mut client, &node_a, vec![], None).await.unwrap();
    let _ = next_message(&mut stream, Duration::from_secs(5)).await;

    store
        .update_udp_endpoints(&info_b.node_id, &["10.9.8.7:42421".to_string()])
        .await
        .unwrap();

    let delta = next_delta(&mut stream, Duration::from_secs(2)).await;
    let updated = delta
        .added_or_updated
        .iter()
        .find(|n| n.node_id == info_b.node_id)
        .unwrap_or_else(|| panic!("Endpoint 变化应作为 added_or_updated 推送：{delta:?}"));
    assert_eq!(
        updated.endpoints,
        vec!["10.9.8.7:42421".to_string()],
        "差量必须携带新 Endpoint"
    );

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn coord_outage_closes_streams_and_restart_delivers_fresh_full_map() {
    let (handle, store, addr) = start_server(LONG, LONG).await;
    let auth_key = auth_key(&store).await;
    let node_a = node_keys();
    let mut client = connect(addr).await;
    let info_a = register(&mut client, &node_a, "node-a", &auth_key).await;

    let mut stream = open_map(&mut client, &node_a, vec![], None).await.unwrap();
    let _ = next_message(&mut stream, Duration::from_secs(5)).await;

    handle.shutdown();
    handle.terminated().await;

    let ended = tokio::time::timeout(Duration::from_secs(5), stream.message()).await;
    assert!(
        matches!(ended, Ok(Ok(None)) | Ok(Err(_))),
        "服务停止后流必须结束：{ended:?}"
    );

    let handle = restart_on_same_addr(&store, addr, LONG, LONG).await;
    let mut client = connect(addr).await;
    let mut stream = open_map(&mut client, &node_a, vec![], None).await.unwrap();
    let message = next_message(&mut stream, Duration::from_secs(5)).await;
    let Kind::Full(map) = message.kind.unwrap() else {
        panic!("重启重连后首条必须是新全量");
    };
    let names: HashSet<String> = map.nodes.iter().map(|n| n.name.clone()).collect();
    assert_eq!(
        names,
        HashSet::from([info_a.name.clone()]),
        "重启后的全量必须来自同一份持久化存储：{names:?}"
    );

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn rebind_rotation_pushes_new_node_key_as_delta() {
    let (handle, store, addr) = start_server(LONG, LONG).await;
    let auth_key = auth_key(&store).await;
    let node_a = node_keys();
    let node_b = node_keys();
    let mut client = connect(addr).await;
    let _info_a = register(&mut client, &node_a, "node-a", &auth_key).await;
    let info_b = register(&mut client, &node_b, "node-b", &auth_key).await;

    let mut stream = open_map(&mut client, &node_a, vec![], None).await.unwrap();
    let _ = next_message(&mut stream, Duration::from_secs(5)).await;

    // 重新登录：同一 Machine Key 换归属与 Node Key（#10 的 bind 路径）。
    let user_id = store.upsert_user("alice", false).await.unwrap();
    let rotated_key = [7u8; 32];
    store
        .bind_node_to_user(
            &node_b.machine.verifying_key().to_bytes(),
            &rotated_key,
            "node-b",
            &user_id,
            hz_coord::store::unix_now() + 3600,
        )
        .await
        .unwrap();

    let delta = next_delta(&mut stream, Duration::from_secs(5)).await;
    let updated = delta
        .added_or_updated
        .iter()
        .find(|node| node.node_id == info_b.node_id)
        .expect("轮换必须立即推给对端，不能等周期清扫");
    assert_eq!(updated.node_key_pub, rotated_key.to_vec());
    assert_eq!(updated.owner_user.as_deref(), Some("alice"));

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn tagged_node_never_gets_an_expiry_but_login_bound_nodes_do() {
    let (handle, store, addr) = start_server(LONG, LONG).await;
    let tagged_key = store
        .create_auth_key(
            chrono::Utc::now().timestamp() + 3600,
            false,
            &["edge".to_string()],
        )
        .await
        .unwrap();
    let mut client = connect(addr).await;
    let tagged = register(&mut client, &node_keys(), "node-tagged", &tagged_key).await;
    assert!(
        tagged.expires_at_unix.is_none() && tagged.owner_user.is_none(),
        "带 Tag 注册的 Node 不归属 User，也永不设置有效期（FR-3）"
    );

    let user_id = store.upsert_user("bob", false).await.unwrap();
    let login_keys = node_keys();
    let bound = store
        .bind_node_to_user(
            &login_keys.machine.verifying_key().to_bytes(),
            &login_keys.node_public,
            "node-bound",
            &user_id,
            hz_coord::store::unix_now() + 60,
        )
        .await
        .unwrap();
    assert_eq!(
        bound.expires_at_unix,
        Some(hz_coord::store::unix_now() + 60),
        "登录绑定的 Node 必须带有效期"
    );

    // 有效期语义落在 map：到期后只有归属 User 的 Node 消失。
    sqlx::query("UPDATE nodes SET expires_at_unix = ?1 WHERE id = ?2")
        .bind(hz_coord::store::unix_now() - 1)
        .bind(&bound.id)
        .execute(store.pool())
        .await
        .unwrap();
    let names: Vec<String> = store
        .network_map()
        .await
        .unwrap()
        .into_iter()
        .map(|record| record.name)
        .collect();
    assert!(names.contains(&"node-tagged".to_string()));
    assert!(!names.contains(&"node-bound".to_string()));

    handle.shutdown();
    handle.terminated().await;
}
