//! Admin 远程管理的服务端契约（FR-11 / A3，真实 tonic over loopback + SQLite）：
//! 三种操作者（Admin / 普通 User / 带 Tag 的 Node）× 六个管理操作的权限矩阵
//! （字面期望值）、改名唯一性、删除的 Map 差量下发、签发 Key 可注册、
//! 吊销 Key 被拒。

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, ServeHandle, serve};
use hz_coord::store::Store;
use hz_proto::coord_client::CoordClient;
use hz_proto::network_map_message::Kind;
use hz_proto::{
    AdminCreateAuthKeyRequest, AdminRevokeAuthKeyRequest, DeleteNodeRequest, HelloRequest,
    ListNodesRequest, PROTOCOL_VERSION, RegisterAuthKeyRequest, RenameNodeRequest,
    RevokeNodeRequest, StreamMapRequest,
};
use rand_core::OsRng;
use tonic::transport::Channel;
use tonic::{Code, Status};
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

async fn start_server() -> (ServeHandle, Store, SocketAddr) {
    let store = Store::open_in_memory(AddressConfig::default())
        .await
        .unwrap();
    let mut config = ServeConfig::new(store.clone(), "127.0.0.1:0".parse().unwrap());
    config.map_keepalive = LONG;
    config.map_sweep = LONG;
    let handle = serve(config).await.unwrap();
    let addr = handle.local_addr;
    (handle, store, addr)
}

async fn connect(addr: SocketAddr) -> CoordClient<Channel> {
    let channel = Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    CoordClient::new(channel)
}

/// Hello → 签挑战，返回管理请求的公共认证字段。
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

async fn register_fresh_auth_key(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    hostname: &str,
    auth_key: &str,
) -> hz_proto::NodeInfo {
    let (nonce, signature) = signed_challenge(client, keys, hostname).await;
    client
        .register_with_auth_key(RegisterAuthKeyRequest {
            invite_code: None,
            challenge_nonce: nonce,
            challenge_signature: signature,
            auth_key: auth_key.to_owned(),
            node_key_pub: keys.node_public.to_vec(),
        })
        .await
        .unwrap()
        .into_inner()
        .node
        .unwrap()
}

async fn auth_key(store: &Store, tags: &[&str]) -> String {
    store
        .create_auth_key(
            hz_coord::store::unix_now() + 3600,
            false,
            &tags.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
        )
        .await
        .unwrap()
}

/// alice(Admin) + bob（普通 User）与各自名下的 Node；db 是带 tag 的无主 Node。
/// 归属绑定复用 #13 的直写库模式（生产路径是交互式登录）。
struct Fleet {
    alice: NodeKeys,
    bob: NodeKeys,
    db: NodeKeys,
    alice_node: hz_proto::NodeInfo,
    bob_node: hz_proto::NodeInfo,
    db_node: hz_proto::NodeInfo,
}

async fn fleet(client: &mut CoordClient<Channel>, store: &Store) -> Fleet {
    let alice_id = store.upsert_user("alice", true).await.unwrap();
    let bob_id = store.upsert_user("bob", false).await.unwrap();
    let plain_key = auth_key(store, &[]).await;
    let db_key = auth_key(store, &["db"]).await;

    let alice = node_keys();
    let bob = node_keys();
    let db = node_keys();
    let alice_node = register_fresh_auth_key(client, &alice, "node-alice", &plain_key).await;
    let bob_node = register_fresh_auth_key(client, &bob, "node-bob", &plain_key).await;
    let db_node = register_fresh_auth_key(client, &db, "node-db", &db_key).await;

    let expires = hz_coord::store::unix_now() + 3600;
    store
        .bind_node_to_user(
            alice.machine.verifying_key().as_bytes(),
            &alice.node_public,
            "node-alice",
            &alice_id,
            expires,
        )
        .await
        .unwrap();
    store
        .bind_node_to_user(
            bob.machine.verifying_key().as_bytes(),
            &bob.node_public,
            "node-bob",
            &bob_id,
            expires,
        )
        .await
        .unwrap();
    Fleet {
        alice,
        bob,
        db,
        alice_node,
        bob_node,
        db_node,
    }
}

// ---- 六个操作的最小调用面（字面期望值直接落在断言里） ----

async fn create_auth_key(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
) -> Result<hz_proto::AdminCreateAuthKeyResponse, Status> {
    create_auth_key_with_tags(client, keys, vec!["ci".to_owned()]).await
}

async fn create_auth_key_with_tags(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    tags: Vec<String>,
) -> Result<hz_proto::AdminCreateAuthKeyResponse, Status> {
    let (nonce, signature) = signed_challenge(client, keys, "admin-op").await;
    client
        .admin_create_auth_key(AdminCreateAuthKeyRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "admin-op".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            expires_unix: hz_coord::store::unix_now() + 3600,
            single_use: false,
            tags,
        })
        .await
        .map(|response| response.into_inner())
}

async fn revoke_auth_key(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    key_id: &str,
) -> Result<(), Status> {
    let (nonce, signature) = signed_challenge(client, keys, "admin-op").await;
    client
        .admin_revoke_auth_key(AdminRevokeAuthKeyRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "admin-op".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            key_id: key_id.to_owned(),
        })
        .await
        .map(|_| ())
}

async fn list_nodes(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
) -> Result<Vec<hz_proto::AdminNodeInfo>, Status> {
    let (nonce, signature) = signed_challenge(client, keys, "admin-op").await;
    client
        .list_nodes(ListNodesRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "admin-op".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
        })
        .await
        .map(|response| response.into_inner().nodes)
}

async fn rename_node(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    node_id: &str,
    new_name: &str,
) -> Result<String, Status> {
    let (nonce, signature) = signed_challenge(client, keys, "admin-op").await;
    client
        .rename_node(RenameNodeRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "admin-op".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            node_id: node_id.to_owned(),
            new_name: new_name.to_owned(),
        })
        .await
        .map(|response| response.into_inner().name)
}

async fn delete_node(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    node_id: &str,
) -> Result<(), Status> {
    let (nonce, signature) = signed_challenge(client, keys, "admin-op").await;
    client
        .delete_node(DeleteNodeRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "admin-op".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            node_id: node_id.to_owned(),
        })
        .await
        .map(|_| ())
}

async fn revoke_node(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    node_id: &str,
) -> Result<(), Status> {
    let (nonce, signature) = signed_challenge(client, keys, "admin-op").await;
    client
        .revoke_node(RevokeNodeRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "admin-op".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            node_id: node_id.to_owned(),
        })
        .await
        .map(|_| ())
}

/// 断言 PermissionDenied 且文案含指定片段。
fn assert_denied(status: &Status, fragment: &str) {
    assert_eq!(status.code(), Code::PermissionDenied, "{status}");
    assert!(
        status.message().contains(fragment),
        "报错应含 {fragment:?}，实际：{}",
        status.message()
    );
}

/// 权限矩阵（AC）：Admin 全通、普通 User 只通查看/改名/删除自己名下、
/// 带 Tag 的 Node 六项全拒。逐格字面断言。
#[tokio::test]
async fn permission_matrix_three_operators_six_ops() {
    let (handle, store, addr) = start_server().await;
    let mut client = connect(addr).await;
    let fleet = fleet(&mut client, &store).await;

    // Admin：签发 → 吊销（刚签的）→ 列表 → 改名（带 Tag 的 Node 也行）。
    let issued = create_auth_key(&mut client, &fleet.alice)
        .await
        .expect("Admin 签发 Auth Key 应成功");
    assert!(!issued.auth_key.is_empty(), "明文 Key 必须返回");
    assert!(!issued.key_id.is_empty(), "key id 必须返回");
    revoke_auth_key(&mut client, &fleet.alice, &issued.key_id)
        .await
        .expect("Admin 吊销 Auth Key 应成功");

    let listed = list_nodes(&mut client, &fleet.alice)
        .await
        .expect("Admin 列表应成功");
    let names: HashSet<String> = listed.iter().map(|n| n.name.clone()).collect();
    assert_eq!(
        names,
        HashSet::from([
            "node-alice".to_string(),
            "node-bob".to_string(),
            "node-db".to_string()
        ]),
        "Admin 看到全部 Node"
    );
    let db_row = listed
        .iter()
        .find(|n| n.node_id == fleet.db_node.node_id)
        .unwrap();
    assert_eq!(db_row.tags, vec!["db".to_string()], "列表行携带 Tag");
    assert!(!db_row.revoked);

    let renamed = rename_node(
        &mut client,
        &fleet.alice,
        &fleet.db_node.node_id,
        "node-db-renamed",
    )
    .await
    .expect("Admin 可改名任意 Node（含带 Tag 的）");
    assert_eq!(renamed, "node-db-renamed");

    // 普通 User：签发/吊销 Auth Key 被拒；列表只有自己；改名/删除仅限
    // 自己名下；吊销 Node 被拒。
    let status = create_auth_key(&mut client, &fleet.bob).await.unwrap_err();
    assert_denied(&status, "需要 Admin 权限");
    let status = revoke_auth_key(&mut client, &fleet.bob, "whatever")
        .await
        .unwrap_err();
    assert_denied(&status, "需要 Admin 权限");

    let listed = list_nodes(&mut client, &fleet.bob)
        .await
        .expect("普通 User 列表应成功");
    let names: Vec<String> = listed.iter().map(|n| n.name.clone()).collect();
    assert_eq!(
        names,
        vec!["node-bob".to_string()],
        "普通 User 只看到自己名下的 Node"
    );

    let status = rename_node(
        &mut client,
        &fleet.bob,
        &fleet.alice_node.node_id,
        "bob-wants",
    )
    .await
    .unwrap_err();
    assert_denied(&status, "只能操作自己名下的 Node");
    let status = delete_node(&mut client, &fleet.bob, &fleet.alice_node.node_id)
        .await
        .unwrap_err();
    assert_denied(&status, "只能操作自己名下的 Node");
    let status = revoke_node(&mut client, &fleet.bob, &fleet.alice_node.node_id)
        .await
        .unwrap_err();
    assert_denied(&status, "需要 Admin 权限");

    // 带 Tag 的 Node：六项管理操作全部拒绝。
    for status in [
        create_auth_key(&mut client, &fleet.db).await.unwrap_err(),
        revoke_auth_key(&mut client, &fleet.db, "k")
            .await
            .unwrap_err(),
        list_nodes(&mut client, &fleet.db).await.unwrap_err(),
        rename_node(&mut client, &fleet.db, &fleet.db_node.node_id, "x")
            .await
            .unwrap_err(),
        delete_node(&mut client, &fleet.db, &fleet.db_node.node_id)
            .await
            .unwrap_err(),
        revoke_node(&mut client, &fleet.db, &fleet.db_node.node_id)
            .await
            .unwrap_err(),
    ] {
        assert_denied(&status, "带 Tag 的 Node 不能执行管理操作");
    }

    // Admin 吊销 Node（矩阵最后一格）：吊销后的行仍在 Admin 列表里供审计。
    revoke_node(&mut client, &fleet.alice, &fleet.bob_node.node_id)
        .await
        .expect("Admin 吊销 Node 应成功");
    let listed = list_nodes(&mut client, &fleet.alice).await.unwrap();
    let bob_row = listed
        .iter()
        .find(|n| n.node_id == fleet.bob_node.node_id)
        .expect("已吊销的行仍对 Admin 可见");
    assert!(bob_row.revoked, "吊销行必须带 revoked 标记");

    handle.shutdown();
    handle.terminated().await;
}

/// 无 Tag 的 Auth Key 会注册出既无归属也无 Tag 的 Node（Policy 覆盖不到）：
/// 签发时即拒绝，旧版 hz 也绕不过。
#[tokio::test]
async fn admin_create_auth_key_requires_a_tag() {
    let (handle, store, addr) = start_server().await;
    let mut client = connect(addr).await;
    let fleet = fleet(&mut client, &store).await;

    let status = create_auth_key_with_tags(&mut client, &fleet.alice, vec![])
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument, "{status}");
    assert!(status.message().contains("Tag"), "{status}");

    handle.shutdown();
    handle.terminated().await;
}

/// Node 要么归属 User、要么带 Tag（GLOSSARY）：带 Tag 的 Node 经交互式登录
/// 归属到 User 后 Tag 清空。
#[tokio::test]
async fn login_binding_clears_tags() {
    let (handle, store, addr) = start_server().await;
    let mut client = connect(addr).await;
    let user_id = store.upsert_user("carol", false).await.unwrap();
    let key = auth_key(&store, &["edge"]).await;
    let keys = node_keys();
    let info = register_fresh_auth_key(&mut client, &keys, "node-edge", &key).await;
    assert_eq!(info.tags, vec!["edge".to_string()]);

    let record = store
        .bind_node_to_user(
            keys.machine.verifying_key().as_bytes(),
            &keys.node_public,
            "node-edge",
            &user_id,
            hz_coord::store::unix_now() + 3600,
        )
        .await
        .unwrap();
    assert_eq!(record.owner_user.as_deref(), Some("carol"));
    assert!(record.tags.is_empty(), "返回值仍带 Tag：{:?}", record.tags);
    let stored = store
        .node_by_machine_key(keys.machine.verifying_key().as_bytes())
        .await
        .unwrap()
        .unwrap();
    assert!(stored.tags.is_empty(), "库里仍带 Tag：{:?}", stored.tags);

    handle.shutdown();
    handle.terminated().await;
}

/// Admin 签发的 Key 注册出真 Node；吊销后同把 Key 再注册被拒。
#[tokio::test]
async fn issued_key_registers_and_revoked_key_is_rejected() {
    let (handle, store, addr) = start_server().await;
    let mut client = connect(addr).await;
    let fleet = fleet(&mut client, &store).await;

    let issued = create_auth_key(&mut client, &fleet.alice)
        .await
        .expect("Admin 签发应成功");
    let newcomer = node_keys();
    let info =
        register_fresh_auth_key(&mut client, &newcomer, "node-fresh", &issued.auth_key).await;
    assert_eq!(info.name, "node-fresh");

    revoke_auth_key(&mut client, &fleet.alice, &issued.key_id)
        .await
        .expect("吊销应成功");
    let another = node_keys();
    let status =
        register_with_auth_key_status(&mut client, &another, "node-second", &issued.auth_key)
            .await
            .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied, "{status}");
    assert!(
        status.message().contains("已过期"),
        "吊销把过期时刻钉到当下之前，注册侧按已过期拒绝：{}",
        status.message()
    );

    // 幂等：再次吊销同一把 Key 仍成功；不存在的 Key 报 NotFound。
    revoke_auth_key(&mut client, &fleet.alice, &issued.key_id)
        .await
        .expect("重复吊销是幂等成功");
    let status = revoke_auth_key(&mut client, &fleet.alice, "no-such-key")
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::NotFound, "{status}");

    handle.shutdown();
    handle.terminated().await;
}

async fn register_with_auth_key_status(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    hostname: &str,
    auth_key: &str,
) -> Result<hz_proto::RegisterResponse, Status> {
    let (nonce, signature) = signed_challenge(client, keys, hostname).await;
    client
        .register_with_auth_key(RegisterAuthKeyRequest {
            invite_code: None,
            challenge_nonce: nonce,
            challenge_signature: signature,
            auth_key: auth_key.to_owned(),
            node_key_pub: keys.node_public.to_vec(),
        })
        .await
        .map(|response| response.into_inner())
}

/// 改名：规范化生效、冲突 AlreadyExists、改完订阅者秒级看到新名。
#[tokio::test]
async fn rename_normalizes_rejects_conflicts_and_reaches_subscribers() {
    let (handle, store, addr) = start_server().await;
    let mut client = connect(addr).await;
    let fleet = fleet(&mut client, &store).await;

    // 打开 bob 的订阅流（改名差量要到达它）。
    let (nonce, signature) = signed_challenge(&mut client, &fleet.bob, "node-bob").await;
    let mut stream_bob = client
        .stream_network_map(StreamMapRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: fleet.bob.machine.verifying_key().to_bytes().to_vec(),
            hostname: "node-bob".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            endpoints: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    let full = tokio::time::timeout(Duration::from_secs(5), stream_bob.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(full.kind, Some(Kind::Full(_))));

    let renamed = rename_node(
        &mut client,
        &fleet.alice,
        &fleet.db_node.node_id,
        "Node DB_01!",
    )
    .await
    .expect("改名应成功");
    assert_eq!(renamed, "node-db-01", "新名按 Node Name 规则规范化");

    let status = rename_node(
        &mut client,
        &fleet.alice,
        &fleet.db_node.node_id,
        "node-alice",
    )
    .await
    .unwrap_err();
    assert_eq!(status.code(), Code::AlreadyExists, "{status}");
    assert!(status.message().contains("Node Name 已存在"), "{}", status);

    // 5 秒内 bob 的订阅流收到含新名的差量。
    let started = std::time::Instant::now();
    let mut saw_new_name = false;
    while !saw_new_name {
        let message = tokio::time::timeout(
            Duration::from_secs(5).saturating_sub(started.elapsed()),
            stream_bob.message(),
        )
        .await
        .expect("5 秒内必须收到改名差量")
        .unwrap()
        .expect("流不应关闭");
        if let Some(Kind::Delta(delta)) = message.kind {
            if delta
                .added_or_updated
                .iter()
                .any(|node| node.name == "node-db-01")
            {
                saw_new_name = true;
            }
        }
    }
    assert!(started.elapsed() < Duration::from_secs(5));

    handle.shutdown();
    handle.terminated().await;
}

/// 删除：订阅对端 5 秒内收到 removed 差量；被删 Node 无法再认证。
#[tokio::test]
async fn delete_removes_node_from_peer_maps_within_five_seconds() {
    let (handle, store, addr) = start_server().await;
    let mut client = connect(addr).await;
    let fleet = fleet(&mut client, &store).await;

    let (nonce, signature) = signed_challenge(&mut client, &fleet.alice, "node-alice").await;
    let mut stream_alice = client
        .stream_network_map(StreamMapRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: fleet.alice.machine.verifying_key().to_bytes().to_vec(),
            hostname: "node-alice".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            endpoints: vec![],
        })
        .await
        .unwrap()
        .into_inner();
    let full = tokio::time::timeout(Duration::from_secs(5), stream_alice.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(full.kind, Some(Kind::Full(_))));

    delete_node(&mut client, &fleet.alice, &fleet.bob_node.node_id)
        .await
        .expect("Admin 删除应成功");

    let started = std::time::Instant::now();
    let mut saw_removed = false;
    while !saw_removed {
        let message = tokio::time::timeout(
            Duration::from_secs(5).saturating_sub(started.elapsed()),
            stream_alice.message(),
        )
        .await
        .expect("5 秒内必须收到删除差量")
        .unwrap()
        .expect("流不应关闭");
        if let Some(Kind::Delta(delta)) = message.kind {
            if delta.removed_node_ids.contains(&fleet.bob_node.node_id) {
                saw_removed = true;
            }
        }
    }
    assert!(started.elapsed() < Duration::from_secs(5));

    // 被删的 Node 连挑战认证都过不去（行已不存在）。
    let (nonce, signature) = signed_challenge(&mut client, &fleet.bob, "node-bob").await;
    let status = client
        .stream_network_map(StreamMapRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: fleet.bob.machine.verifying_key().to_bytes().to_vec(),
            hostname: "node-bob".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            endpoints: vec![],
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied, "{status}");
    assert!(status.message().contains("未注册或已吊销"), "{}", status);

    handle.shutdown();
    handle.terminated().await;
}
