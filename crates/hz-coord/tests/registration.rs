//! Seam B：Auth Key 注册全链路（真实 tonic over loopback + 内存 SQLite）。

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};

use ed25519_dalek::{Signer, SigningKey};
use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, ServeHandle, serve};
use hz_coord::store::Store;
use hz_proto::coord_client::CoordClient;
use hz_proto::{HelloRequest, PROTOCOL_VERSION, RegisterAuthKeyRequest};
use rand_core::OsRng;
use sqlx::Row;
use tonic::transport::Channel;
use tonic::{Response, Status};
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
    let handle = serve(ServeConfig::new(store.pool().clone(), listen))
        .await
        .unwrap();
    TestServer { handle, store }
}

fn uri(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

async fn connect(addr: SocketAddr) -> CoordClient<Channel> {
    let channel = Channel::from_shared(uri(addr))
        .unwrap()
        .connect()
        .await
        .unwrap();
    CoordClient::new(channel)
}

async fn hello(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    hostname: &str,
) -> hz_proto::HelloResponse {
    client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: hostname.to_owned(),
        })
        .await
        .unwrap()
        .into_inner()
}

async fn register(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    nonce: Vec<u8>,
    auth_key: &str,
) -> Result<Response<hz_proto::RegisterResponse>, Status> {
    let signature = keys.machine.sign(&nonce).to_bytes().to_vec();
    client
        .register_with_auth_key(RegisterAuthKeyRequest {
            challenge_nonce: nonce,
            challenge_signature: signature,
            auth_key: auth_key.to_owned(),
            node_key_pub: keys.node_public.to_vec(),
        })
        .await
}

async fn register_fresh(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    hostname: &str,
    auth_key: &str,
) -> Result<Response<hz_proto::RegisterResponse>, Status> {
    let hello = hello(client, keys, hostname).await;
    register(client, keys, hello.challenge_nonce, auth_key).await
}

fn future_unix(secs: i64) -> i64 {
    chrono::Utc::now().timestamp() + secs
}

#[tokio::test]
async fn one_time_auth_key_second_use_is_rejected_as_used() {
    let server = start_server().await;
    let auth_key = server
        .store
        .create_auth_key(future_unix(3600), true, &[])
        .await
        .unwrap();

    let first = node_keys();
    let second = node_keys();
    let mut client = connect(server.handle.local_addr).await;

    let ok = register_fresh(&mut client, &first, "node-a", &auth_key).await;
    assert!(ok.is_ok(), "首次使用一次性 Key 应注册成功：{ok:?}");

    let rejected = register_fresh(&mut client, &second, "node-b", &auth_key).await;
    let status = rejected.expect_err("第二次使用必须被拒绝");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert!(
        status.message().contains("已使用"),
        "实际信息：{}",
        status.message()
    );

    server.handle.shutdown();
    server.handle.terminated().await;
}

#[tokio::test]
async fn expired_auth_key_is_rejected_as_expired() {
    let server = start_server().await;
    // 过期时间直接落在过去。
    let auth_key = server
        .store
        .create_auth_key(chrono::Utc::now().timestamp() - 60, true, &[])
        .await
        .unwrap();

    let keys = node_keys();
    let mut client = connect(server.handle.local_addr).await;
    let rejected = register_fresh(&mut client, &keys, "node-a", &auth_key).await;
    let status = rejected.expect_err("过期 Key 必须被拒绝");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert!(
        status.message().contains("已过期"),
        "实际信息：{}",
        status.message()
    );

    server.handle.shutdown();
    server.handle.terminated().await;
}

#[tokio::test]
async fn tagged_auth_key_grants_tags_without_owner() {
    let server = start_server().await;
    let auth_key = server
        .store
        .create_auth_key(future_unix(3600), true, &["db".to_string()])
        .await
        .unwrap();

    let keys = node_keys();
    let mut client = connect(server.handle.local_addr).await;
    let response = register_fresh(&mut client, &keys, "db-1", &auth_key)
        .await
        .unwrap()
        .into_inner();
    let node = response.node.unwrap();
    assert_eq!(node.tags, vec!["db".to_string()]);
    assert_eq!(node.owner_user, None);

    let row = sqlx::query("SELECT tags, user_id FROM nodes WHERE id = ?1")
        .bind(&node.node_id)
        .fetch_one(server.store.pool())
        .await
        .unwrap();
    let tags: String = row.get("tags");
    assert_eq!(tags, r#"["db"]"#);
    let user_id: Option<String> = row.get("user_id");
    assert_eq!(user_id, None, "Tag 注册的 Node 不归属任何 User");

    server.handle.shutdown();
    server.handle.terminated().await;
}

#[tokio::test]
async fn three_nodes_get_distinct_addresses_sharing_one_ula_prefix() {
    let server = start_server().await;
    let mut client = connect(server.handle.local_addr).await;

    let mut ipv4s = HashSet::new();
    let mut ipv6s = HashSet::new();
    let mut ula_prefixes = HashSet::new();
    for i in 0..3 {
        let auth_key = server
            .store
            .create_auth_key(future_unix(3600), true, &[])
            .await
            .unwrap();
        let keys = node_keys();
        let response = register_fresh(&mut client, &keys, &format!("node-{i}"), &auth_key)
            .await
            .unwrap()
            .into_inner();
        let node = response.node.unwrap();

        let ipv4: Ipv4Addr = node.ipv4.parse().unwrap();
        assert!(
            AddressConfig::default().cidr.contains(ipv4),
            "地址必须落在 100.96.0.0/16：{ipv4}"
        );
        assert_ne!(ipv4, Ipv4Addr::new(100, 96, 0, 53), "保留地址不得分配");
        assert!(ipv4s.insert(ipv4), "IPv4 不得重复：{ipv4}");

        let ipv6: std::net::Ipv6Addr = node.ipv6.parse().unwrap();
        assert!(ipv6.segments()[0] >> 8 == 0xfd, "必须是 ULA：{ipv6}");
        assert!(ipv6s.insert(ipv6), "IPv6 不得重复：{ipv6}");
        ula_prefixes.insert([ipv6.segments()[0], ipv6.segments()[1], ipv6.segments()[2]]);
    }
    assert_eq!(ula_prefixes.len(), 1, "所有 Node 共用一个 ULA /48 前缀");

    server.handle.shutdown();
    server.handle.terminated().await;
}

#[tokio::test]
async fn duplicate_hostnames_get_numeric_suffixes() {
    let server = start_server().await;
    let mut client = connect(server.handle.local_addr).await;

    let first = node_keys();
    let second = node_keys();
    let key_one = server
        .store
        .create_auth_key(future_unix(3600), true, &[])
        .await
        .unwrap();
    let key_two = server
        .store
        .create_auth_key(future_unix(3600), true, &[])
        .await
        .unwrap();

    let first_name = register_fresh(&mut client, &first, "Host A", &key_one)
        .await
        .unwrap()
        .into_inner()
        .node
        .unwrap()
        .name;
    let second_name = register_fresh(&mut client, &second, "Host A", &key_two)
        .await
        .unwrap()
        .into_inner()
        .node
        .unwrap()
        .name;

    assert_eq!(first_name, "host-a");
    assert_eq!(second_name, "host-a-2");

    server.handle.shutdown();
    server.handle.terminated().await;
}

#[tokio::test]
async fn wrong_machine_key_signature_is_unauthenticated() {
    let server = start_server().await;
    let auth_key = server
        .store
        .create_auth_key(future_unix(3600), true, &[])
        .await
        .unwrap();

    let hello_keys = node_keys();
    let signing_keys = node_keys();
    let mut client = connect(server.handle.local_addr).await;

    let hello = hello(&mut client, &hello_keys, "node-a").await;
    let rejected = register(&mut client, &signing_keys, hello.challenge_nonce, &auth_key).await;
    let status = rejected.expect_err("错误签名必须被拒绝");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert!(
        status.message().contains("签名"),
        "实际信息：{}",
        status.message()
    );

    server.handle.shutdown();
    server.handle.terminated().await;
}

#[tokio::test]
async fn protocol_version_zero_is_rejected_with_upgrade_hint() {
    let server = start_server().await;
    let keys = node_keys();
    let mut client = connect(server.handle.local_addr).await;

    let status = client
        .hello(HelloRequest {
            protocol_version: 0,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "node-a".to_owned(),
        })
        .await
        .expect_err("协议版本 0 必须被拒绝");

    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    let message = status.message();
    assert!(message.contains("客户端版本过旧"), "实际信息：{message}");
    assert!(
        message.contains('1'),
        "提示里必须包含最低支持版本 1：{message}"
    );

    server.handle.shutdown();
    server.handle.terminated().await;
}

#[tokio::test]
async fn auth_key_plaintext_is_never_stored_but_hash_lookup_works() {
    let server = start_server().await;
    let auth_key = server
        .store
        .create_auth_key(future_unix(3600), true, &["secret-tag".to_string()])
        .await
        .unwrap();
    assert!(auth_key.starts_with("hznet."));

    let rows = sqlx::query("SELECT id, key_hash, created_at_unix, expires_at_unix, single_use, used_at_unix, tags FROM auth_keys")
        .fetch_all(server.store.pool())
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    for row in &rows {
        for value in [
            row.try_get::<String, _>("id"),
            row.try_get::<String, _>("key_hash"),
            row.try_get::<String, _>("tags"),
        ]
        .into_iter()
        .flatten()
        {
            assert!(
                !value.contains(&auth_key),
                "auth_keys 任何列都不得包含明文 Key"
            );
        }
    }

    let consumed = server.store.consume_auth_key(&auth_key).await;
    assert!(
        consumed.is_ok(),
        "按明文哈希必须能查到这条 Key：{consumed:?}"
    );

    server.handle.shutdown();
    server.handle.terminated().await;
}

#[tokio::test]
async fn migrations_are_idempotent_on_the_same_pool() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("coord.db"), AddressConfig::default())
        .await
        .unwrap();
    sqlx::migrate!("./migrations")
        .run(store.pool())
        .await
        .expect("在同一连接池上重复迁移不应报错");
}
