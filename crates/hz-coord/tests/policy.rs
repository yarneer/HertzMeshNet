//! Policy 的服务端契约（真实 tonic over loopback + SQLite）：校验整份拒绝、
//! 版本历史与回滚（含引用失效后的回滚拒绝）、按订阅者过滤的 Network Map
//! （ADR-0006 组合矩阵）、5 秒内的差量下发、A3 管理授权。

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, ServeHandle, serve};
use hz_coord::store::Store;
use hz_proto::coord_client::CoordClient;
use hz_proto::network_map_message::Kind;
use hz_proto::{
    HelloRequest, PROTOCOL_VERSION, PolicyGetRequest, PolicyPushRequest, PolicyRollbackRequest,
    RegisterAuthKeyRequest, StreamMapRequest,
};
use rand_core::OsRng;
use tonic::transport::Channel;
use tonic::{Code, Response, Status};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

const LONG: Duration = Duration::from_secs(3600);
const DEV_DB_5432: &str = "[[group]]\nname = \"dev\"\nusers = [\"alice\"]\n\
     [[rule]]\nfrom = \"group:dev\"\nto = \"tag:db\"\nports = [5432]\n";

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

async fn auth_key(store: &Store, tags: &[&str]) -> String {
    store
        .create_auth_key(
            chrono::Utc::now().timestamp() + 3600,
            false,
            &tags.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
        )
        .await
        .unwrap()
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
    client
        .register_with_auth_key(RegisterAuthKeyRequest {
            challenge_nonce: hello.challenge_nonce.clone(),
            challenge_signature: keys
                .machine
                .sign(&hello.challenge_nonce)
                .to_bytes()
                .to_vec(),
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

async fn open_map(client: &mut CoordClient<Channel>, keys: &NodeKeys, hostname: &str) -> MapStream {
    let hello = client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: hostname.to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    client
        .stream_network_map(StreamMapRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: hostname.to_owned(),
            challenge_nonce: hello.challenge_nonce.clone(),
            challenge_signature: keys
                .machine
                .sign(&hello.challenge_nonce)
                .to_bytes()
                .to_vec(),
            endpoints: vec![],
        })
        .await
        .unwrap()
        .into_inner()
}

async fn signed_policy_request(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
) -> (Vec<u8>, Vec<u8>) {
    let hello = client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "policy-client".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();
    let signature = keys
        .machine
        .sign(&hello.challenge_nonce)
        .to_bytes()
        .to_vec();
    (hello.challenge_nonce, signature)
}

async fn push(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    content: &str,
) -> Result<i64, Status> {
    let (nonce, signature) = signed_policy_request(client, keys).await;
    client
        .policy_push(PolicyPushRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "policy-client".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            content: content.to_owned(),
        })
        .await
        .map(|response: Response<hz_proto::PolicyPushResponse>| response.into_inner().version)
}

async fn rollback(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    version: i64,
) -> Result<i64, Status> {
    let (nonce, signature) = signed_policy_request(client, keys).await;
    client
        .policy_rollback(PolicyRollbackRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "policy-client".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
            version,
        })
        .await
        .map(|response| response.into_inner().version)
}

async fn get(client: &mut CoordClient<Channel>, keys: &NodeKeys) -> hz_proto::PolicyGetResponse {
    let (nonce, signature) = signed_policy_request(client, keys).await;
    client
        .policy_get(PolicyGetRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().to_bytes().to_vec(),
            hostname: "policy-client".to_owned(),
            challenge_nonce: nonce,
            challenge_signature: signature,
        })
        .await
        .unwrap()
        .into_inner()
}

async fn next_message(stream: &mut MapStream, timeout: Duration) -> hz_proto::NetworkMapMessage {
    tokio::time::timeout(timeout, stream.message())
        .await
        .unwrap_or_else(|_| panic!("{timeout:?} 内未收到下一条 Map 消息"))
        .unwrap()
        .unwrap()
}

/// alice(Admin) + bob 的身份，与各自名下的 Node；db 是带 tag 的无主 Node。
struct Fleet {
    alice: NodeKeys,
    bob: NodeKeys,
    db: NodeKeys,
}

async fn fleet(client: &mut CoordClient<Channel>, store: &Store) -> Fleet {
    let alice_id = store.upsert_user("alice", true).await.unwrap();
    let bob_id = store.upsert_user("bob", false).await.unwrap();
    let plain_key = auth_key(store, &[]).await;
    let db_key = auth_key(store, &["db"]).await;

    let alice = node_keys();
    let bob = node_keys();
    let db = node_keys();
    let info_alice = register(client, &alice, "node-alice", &plain_key).await;
    let info_bob = register(client, &bob, "node-bob", &plain_key).await;
    let info_db = register(client, &db, "node-db", &db_key).await;

    // Auth Key 注册的 Node 无归属；绑定到 users 模拟交互式登录的归属结果。
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
    let _ = (info_alice, info_bob, info_db);
    Fleet { alice, bob, db }
}

fn peer_names(map: &hz_proto::NetworkMap) -> HashSet<String> {
    map.nodes.iter().map(|n| n.name.clone()).collect()
}

#[tokio::test]
async fn push_rejects_invalid_documents_wholesale_and_keeps_current() {
    let (handle, store, addr) = start_server().await;
    let mut client = connect(addr).await;
    let fleet = fleet(&mut client, &store).await;

    let version = push(&mut client, &fleet.alice, DEV_DB_5432)
        .await
        .expect("合法 Policy 应通过");
    assert_eq!(version, 1, "首份 Policy 的版本号从 1 开始");

    let cases = [
        ("这不是 toml [[", "TOML 解析失败"),
        (
            "[[rule]]\nfrom = \"group:nope\"\nto = \"tag:db\"\nports = [80]",
            "未定义的 Group",
        ),
        (
            "[[rule]]\nfrom = \"user:ghost\"\nto = \"tag:db\"\nports = [80]",
            "不存在",
        ),
        (
            "[[rule]]\nfrom = \"tag:Bad!\"\nto = \"tag:db\"\nports = [80]",
            "不符合",
        ),
        (
            "[[rule]]\nfrom = \"tag:ok\"\nto = \"tag:db\"\nports = [70000]",
            "超出范围",
        ),
    ];
    for (content, fragment) in cases {
        let status = push(&mut client, &fleet.alice, content).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{status}");
        assert!(
            status.message().contains(fragment),
            "{content:?} 的报错应含 {fragment:?}，实际：{}",
            status.message()
        );
        let current = get(&mut client, &fleet.alice).await;
        assert_eq!(current.version, 1, "整份拒绝：现行版本不变");
        assert_eq!(
            current.content.as_deref(),
            Some(DEV_DB_5432),
            "整份拒绝：现行内容不变"
        );
    }

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn history_is_listed_and_rollback_round_trips_and_rejects_stale_refs() {
    let (handle, store, addr) = start_server().await;
    let mut client = connect(addr).await;
    let fleet = fleet(&mut client, &store).await;

    // v1 引用 zed（此后会被删掉，用于回滚失效断言）；v2 是常规收紧。
    store.upsert_user("zed", true).await.unwrap();
    let v1 = "[[rule]]\nfrom = \"user:zed\"\nto = \"tag:db\"\nports = [80]\n";
    push(&mut client, &fleet.alice, v1).await.unwrap();
    let v2 = push(&mut client, &fleet.alice, DEV_DB_5432).await.unwrap();
    assert_eq!(v2, 2);

    let current = get(&mut client, &fleet.alice).await;
    assert_eq!(current.version, 2);
    assert_eq!(current.content.as_deref(), Some(DEV_DB_5432));
    let history: Vec<(i64, i64)> = current
        .history
        .iter()
        .map(|entry| (entry.version, entry.created_at_unix))
        .collect();
    assert_eq!(
        history.iter().map(|(v, _)| *v).collect::<Vec<_>>(),
        vec![2, 1],
        "历史按版本倒序、含当前版本"
    );
    assert!(
        history.iter().all(|(_, created)| *created > 0),
        "历史条目带创建时间：{history:?}"
    );

    // 回滚到 v1：内容仍可校验（zed 还在）。
    let rolled = rollback(&mut client, &fleet.alice, 1).await.unwrap();
    assert_eq!(rolled, 1);
    let current = get(&mut client, &fleet.alice).await;
    assert_eq!(current.version, 1, "回滚后当前版本指向 v1");
    assert_eq!(current.content.as_deref(), Some(v1));
    assert_eq!(current.history.len(), 2, "回滚不产生新版本");

    // zed 被删后，v1 引用失效：回滚 v1 被拒，且现行版本不变。
    sqlx::query("DELETE FROM users WHERE name = 'zed'")
        .execute(store.pool())
        .await
        .unwrap();
    let status = rollback(&mut client, &fleet.alice, 1).await.unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument, "{status}");
    assert!(
        status.message().contains("zed"),
        "报错应点名失效引用：{}",
        status.message()
    );
    let current = get(&mut client, &fleet.alice).await;
    assert_eq!(current.version, 1, "回滚被拒不改变现行版本");

    // 回滚到不存在的版本也被拒。
    let status = rollback(&mut client, &fleet.alice, 99).await.unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument, "{status}");
    assert!(status.message().contains("99"));

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn map_streams_are_filtered_per_subscriber_by_policy() {
    let (handle, store, addr) = start_server().await;
    let mut client = connect(addr).await;
    let fleet = fleet(&mut client, &store).await;

    let mut stream_alice = open_map(&mut client, &fleet.alice, "node-alice").await;
    let mut stream_bob = open_map(&mut client, &fleet.bob, "node-bob").await;
    let mut stream_db = open_map(&mut client, &fleet.db, "node-db").await;

    let mut view_alice = hz_proto::NetworkMap::default();
    let mut view_bob = hz_proto::NetworkMap::default();
    let mut view_db = hz_proto::NetworkMap::default();
    for (stream, view, label) in [
        (&mut stream_alice, &mut view_alice, "alice"),
        (&mut stream_bob, &mut view_bob, "bob"),
        (&mut stream_db, &mut view_db, "db"),
    ] {
        let message = next_message(stream, Duration::from_secs(5)).await;
        let Kind::Full(map) = message.kind.unwrap() else {
            panic!("{label} 的首条必须是全量");
        };
        assert!(message.policy.is_none(), "无 Policy 时不应携带 Policy 视图");
        assert_eq!(
            peer_names(&map).len(),
            3,
            "无 Policy bootstrap 全互通（{label}）"
        );
        *view = map;
    }

    let version = push(&mut client, &fleet.alice, DEV_DB_5432).await.unwrap();
    assert_eq!(version, 1);

    // alice：视图剩 [alice, db]；bob：只剩自己；db：剩 [db, alice]。
    let (view, policy) = fold_stream(&mut stream_alice, view_alice).await;
    assert_eq!(
        peer_names(&view),
        HashSet::from(["node-alice".to_string(), "node-db".to_string()]),
        "dev 成员可见 db，不见 bob"
    );
    let policy = policy.expect("alice 的消息应携带 Policy 视图");
    assert_eq!(policy.version, 1);
    assert!(
        policy.inbound_rules.is_empty(),
        "没有规则指向 alice 的 Node：无入站规则（默认全拒）"
    );

    let (view, policy) = fold_stream(&mut stream_bob, view_bob).await;
    assert_eq!(
        peer_names(&view),
        HashSet::from(["node-bob".to_string()]),
        "非 dev 成员的 Map 里没有 db（Seam A 断言的服务端面）"
    );
    assert_eq!(
        policy.expect("bob 也应知道 Policy 版本").version,
        1,
        "版本号对每个订阅者下发，即使入站规则为空"
    );
    let (view, policy) = fold_stream(&mut stream_db, view_db).await;
    assert_eq!(
        peer_names(&view),
        HashSet::from(["node-db".to_string(), "node-alice".to_string()]),
        "可见性方向无关：db 也看见 alice"
    );
    let policy = policy.expect("db 应收到 Policy 视图");
    assert_eq!(policy.version, 1);
    assert_eq!(policy.inbound_rules.len(), 1);
    assert_eq!(policy.inbound_rules[0].from, "group:dev");
    assert_eq!(policy.inbound_rules[0].ports, vec![5432]);
    assert_eq!(policy.groups.len(), 1);
    assert_eq!(policy.groups[0].users, vec!["alice".to_string()]);

    // 回滚到无 Policy 的状态不存在；再推一份允许 22 的 Policy，视图随之放宽。
    push(
        &mut client,
        &fleet.alice,
        "[[group]]\nname = \"dev\"\nusers = [\"alice\"]\n\
         [[rule]]\nfrom = \"group:dev\"\nto = \"tag:db\"\nports = [5432, 22]\n",
    )
    .await
    .unwrap();
    let (_, policy) = fold_stream(&mut stream_db, hz_proto::NetworkMap::default()).await;
    let policy = policy.expect("版本 2 也要送达 db");
    assert_eq!(policy.version, 2);
    assert_eq!(policy.inbound_rules[0].ports, vec![5432, 22]);

    handle.shutdown();
    handle.terminated().await;
}

/// 消费流上已排队的消息到"不再有新消息"为止，折叠出当前全量视图。
async fn fold_stream(
    stream: &mut MapStream,
    initial: hz_proto::NetworkMap,
) -> (hz_proto::NetworkMap, Option<hz_proto::PolicyView>) {
    let mut view = initial;
    let mut policy = None;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let wait = (deadline - Instant::now()).max(Duration::from_millis(50));
        let message = match tokio::time::timeout(wait, stream.message()).await {
            Ok(Ok(Some(message))) => message,
            _ => return (view, policy),
        };
        if let Some(seen) = message.policy {
            policy = Some(seen);
        }
        match message.kind {
            Some(Kind::Full(map)) => view = map,
            Some(Kind::Delta(delta)) => {
                for node in delta.added_or_updated {
                    view.nodes.retain(|n| n.node_id != node.node_id);
                    view.nodes.push(node);
                }
                view.nodes
                    .retain(|n| !delta.removed_node_ids.contains(&n.node_id));
            }
            None => {}
        }
    }
}

#[tokio::test]
async fn policy_change_reaches_subscribers_within_five_seconds() {
    let (handle, store, addr) = start_server().await;
    let mut client = connect(addr).await;
    let fleet = fleet(&mut client, &store).await;

    let mut stream_db = open_map(&mut client, &fleet.db, "node-db").await;
    let _ = next_message(&mut stream_db, Duration::from_secs(5)).await;

    let started = Instant::now();
    push(&mut client, &fleet.alice, DEV_DB_5432).await.unwrap();
    let mut saw_update = false;
    let deadline = Duration::from_secs(5);
    while !saw_update {
        let message = tokio::time::timeout(
            deadline.saturating_sub(started.elapsed()),
            stream_db.message(),
        )
        .await
        .expect("5 秒内必须收到 Policy 更新")
        .unwrap()
        .expect("流不应关闭");
        if message.policy.as_ref().is_some_and(|p| p.version == 1) {
            saw_update = true;
        }
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "Policy 变更 {elapsed:?} 才送达，超过 5 秒 AC"
    );

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn push_and_rollback_require_admin_owner() {
    let (handle, store, addr) = start_server().await;
    let mut client = connect(addr).await;
    let fleet = fleet(&mut client, &store).await;

    let status = push(&mut client, &fleet.db, DEV_DB_5432).await.unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied, "{status}");
    assert!(
        status.message().contains("带 Tag"),
        "A3：带 Tag 的 Node 不能执行管理操作：{}",
        status.message()
    );

    let status = push(&mut client, &fleet.bob, DEV_DB_5432)
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied, "{status}");
    assert!(
        status.message().contains("不是 Admin"),
        "非 Admin 归属被拒：{}",
        status.message()
    );

    push(&mut client, &fleet.alice, DEV_DB_5432)
        .await
        .expect("Admin 归属的 Node 可推送");

    let status = rollback(&mut client, &fleet.bob, 1).await.unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied, "{status}");

    // get 是只读操作：非 Admin 也能查看。
    let current = get(&mut client, &fleet.bob).await;
    assert_eq!(current.version, 1);

    handle.shutdown();
    handle.terminated().await;
}
