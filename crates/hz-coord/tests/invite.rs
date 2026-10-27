//! 邀请码注册（#55）：短码生成与核销、归属/Tag/有效期、单次与多次、
//! 过期与错码、按 IP 限速、权限与明文不落库。全部走真实 gRPC 路径。
use ed25519_dalek::Signer;
use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, serve};
use hz_coord::store::Store;
use hz_proto::coord_client::CoordClient;
use hz_proto::{HelloRequest, PROTOCOL_VERSION, RegisterAuthKeyRequest, RegisterResponse};
use rand_core::OsRng;
use tonic::transport::Channel;
use tonic::{Code, Status};

struct NodeKeys {
    machine: ed25519_dalek::SigningKey,
    node: x25519_dalek::StaticSecret,
}

fn node_keys() -> NodeKeys {
    NodeKeys {
        machine: ed25519_dalek::SigningKey::generate(&mut OsRng),
        node: x25519_dalek::StaticSecret::random_from_rng(OsRng),
    }
}

async fn start() -> (Store, hz_coord::service::ServeHandle, CoordClient<Channel>) {
    let store = Store::open_in_memory(AddressConfig::default())
        .await
        .unwrap();
    store.upsert_user("boss", true).await.unwrap();
    let handle = serve(ServeConfig::new(
        store.clone(),
        "127.0.0.1:0".parse().unwrap(),
    ))
    .await
    .unwrap();
    let channel = Channel::from_shared(format!("http://{}", handle.local_addr))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (store, handle, CoordClient::new(channel))
}

async fn register(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    hostname: &str,
    auth_key: &str,
    invite: Option<&str>,
) -> Result<RegisterResponse, Status> {
    let hello = client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: keys.machine.verifying_key().as_bytes().to_vec(),
            hostname: hostname.to_owned(),
        })
        .await?
        .into_inner();
    let signature = keys
        .machine
        .sign(&hello.challenge_nonce)
        .to_bytes()
        .to_vec();
    let response = client
        .register_with_auth_key(RegisterAuthKeyRequest {
            challenge_nonce: hello.challenge_nonce,
            challenge_signature: signature,
            auth_key: auth_key.to_owned(),
            invite_code: invite.map(str::to_string),
            node_key_pub: x25519_dalek::PublicKey::from(&keys.node)
                .as_bytes()
                .to_vec(),
        })
        .await?;
    Ok(response.into_inner())
}

fn err_text(status: &Status) -> String {
    status.message().to_string()
}

#[tokio::test]
async fn invite_registers_owned_node_with_expiry_and_single_use() {
    let (store, handle, mut client) = start().await;
    // 邀请创建走 store 直调等价于 Admin CLI 的落点（CLI 层另有权限矩阵测试）。
    store.upsert_user("alice", false).await.unwrap();
    let code = store
        .create_invite("boss", 15 * 60, 1, &[], Some(("alice".to_string(), 90)))
        .await
        .unwrap();
    assert!(code.starts_with("HZ-"), "码形应为 HZ-XXXX-XXXX：{code}");

    let invited = node_keys();
    let response = register(&mut client, &invited, "node-invited", "", Some(&code))
        .await
        .unwrap();
    let node = response.node.unwrap();
    assert_eq!(node.owner_user.as_deref(), Some("alice"));
    assert!(node.expires_at_unix.unwrap() > chrono::Utc::now().timestamp());
    assert!(node.tags.is_empty());

    // 单次邀请：第二个节点复用同一码被拒。
    let second = node_keys();
    let rejected = register(&mut client, &second, "node-second", "", Some(&code)).await;
    let status = rejected.expect_err("单次邀请码应只能用一次");
    assert_eq!(status.code(), Code::PermissionDenied);
    assert!(
        err_text(&status).contains("已使用"),
        "实际：{}",
        err_text(&status)
    );

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn invite_with_tags_makes_unowned_node() {
    let (store, handle, mut client) = start().await;
    let code = store
        .create_invite("boss", 15 * 60, 1, &["db".to_string()], None)
        .await
        .unwrap();

    let invited = node_keys();
    let response = register(&mut client, &invited, "tagged-node", "", Some(&code))
        .await
        .unwrap();
    let node = response.node.unwrap();
    assert_eq!(node.tags, vec!["db".to_string()]);
    assert_eq!(node.owner_user, None);
    assert_eq!(node.expires_at_unix, None, "带 Tag 邀请的节点不过期");

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn invite_multi_use_expires_and_wrong_code_rejected() {
    let (store, handle, mut client) = start().await;
    let code = store
        .create_invite("boss", 1, 2, &["ci".to_string()], None)
        .await
        .unwrap();

    for host in ["n1", "n2"] {
        let keys = node_keys();
        let ok = register(&mut client, &keys, host, "", Some(&code)).await;
        assert!(ok.is_ok(), "uses=2 内的第 {host} 次应成功");
    }
    let third = node_keys();
    let exhausted = register(&mut client, &third, "n3", "", Some(&code)).await;
    let status = exhausted.expect_err("第 3 次应被拒");
    assert!(err_text(&status).contains("已使用"));

    // 错码：可读原因；再验证过期。
    let wrong = node_keys();
    let bad = register(&mut client, &wrong, "n4", "", Some("HZ-WRONG-CODE")).await;
    let status = bad.expect_err("不存在的邀请码应被拒");
    assert_eq!(status.code(), Code::PermissionDenied);
    assert!(err_text(&status).contains("无效") || err_text(&status).contains("邀请"));

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let late = node_keys();
    let expired = register(&mut client, &late, "n5", "", Some(&code)).await;
    let status = expired.expect_err("过期码应被拒（即便还有余量）");
    assert!(err_text(&status).contains("过期"));

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn invite_plaintext_never_stored() {
    let (store, handle, _client) = start().await;
    store.upsert_user("alice", false).await.unwrap();
    let code = store
        .create_invite("boss", 60, 1, &[], Some(("alice".to_string(), 90)))
        .await
        .unwrap();
    handle.shutdown();
    handle.terminated().await;

    let dump: String = {
        let pool = store.pool();
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT key, value FROM meta UNION ALL SELECT id, code_hash FROM invites",
        )
        .fetch_all(pool)
        .await
        .unwrap();
        rows.into_iter().map(|(a, b)| format!("{a}={b}")).collect()
    };
    assert!(!dump.contains(&code), "库中不得出现邀请码明文");
    assert!(dump.contains(&sha256_hex(&code)), "库中应有码的 sha256");
}

fn sha256_hex(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(text.trim_start_matches("HZ-").replace('-', "").as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn failed_attempts_are_rate_limited_per_client() {
    let (store, handle, mut client) = start().await;
    let _ = store.create_invite("boss", 60, 1, &[], None).await.unwrap();
    for i in 0..10 {
        let keys = node_keys();
        let bad = register(
            &mut client,
            &keys,
            &format!("brute-{i}"),
            "",
            Some("HZ-AAAA-AAAA"),
        )
        .await;
        assert!(bad.is_err(), "错码必须被拒");
    }
    let eleventh = node_keys();
    let throttled = register(&mut client, &eleventh, "brute-11", "", Some("HZ-AAAA-AAAA")).await;
    let status = throttled.expect_err("连续失败后应触发限速");
    assert_eq!(status.code(), Code::ResourceExhausted, "限速用 429 语义");
    assert!(
        err_text(&status).contains("频繁"),
        "实际：{}",
        err_text(&status)
    );

    handle.shutdown();
    handle.terminated().await;
}
