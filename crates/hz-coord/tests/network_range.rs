//! 地址段配置（#20 / FR-4）：--cidr 落 meta 固化，空库可改段，有节点时
//! 拒绝并给出处置指引；注册响应把生效段与推导的 DNS 地址带给 Node。
use ed25519_dalek::Signer;
use hz_coord::service::{ServeConfig, serve};
use hz_coord::store::{RangeFlags, Store};
use hz_proto::coord_client::CoordClient;
use hz_proto::{HelloRequest, PROTOCOL_VERSION, RegisterAuthKeyRequest};
use rand_core::OsRng;
use tonic::transport::Channel;

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

fn node_public(keys: &NodeKeys) -> Vec<u8> {
    x25519_dalek::PublicKey::from(&keys.node)
        .as_bytes()
        .to_vec()
}

fn tmp_db(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("hznet-range-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("coord.db")
}

async fn start(store: Store) -> (hz_coord::service::ServeHandle, CoordClient<Channel>) {
    let handle = serve(ServeConfig::new(
        store,
        "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap(),
    ))
    .await
    .unwrap();
    let channel = Channel::from_shared(format!("http://{}", handle.local_addr))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (handle, CoordClient::new(channel))
}

/// 走完整 Hello→挑战签名→注册路径，返回注册响应。
async fn register_fresh(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    hostname: &str,
    auth_key: &str,
) -> Result<hz_proto::RegisterResponse, tonic::Status> {
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
            invite_code: None,
            challenge_nonce: hello.challenge_nonce,
            challenge_signature: signature,
            auth_key: auth_key.to_owned(),
            node_key_pub: node_public(keys),
        })
        .await?;
    Ok(response.into_inner())
}

async fn auth_key(store: &Store) -> String {
    store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, true, &[])
        .await
        .unwrap()
}

#[tokio::test]
async fn custom_cidr_allocates_registers_and_announces_the_range() {
    let db = tmp_db("persist");
    let store = Store::open_with_range(
        &db,
        RangeFlags {
            cidr: Some("10.44.0.0/24".to_string()),
            reserve: vec!["10.44.0.7".parse().unwrap()],
        },
    )
    .await
    .unwrap();
    let key = auth_key(&store).await;
    let (handle, mut client) = start(store).await;

    let keys = node_keys();
    let response = register_fresh(&mut client, &keys, "node-a", &key)
        .await
        .unwrap();
    assert_eq!(response.node.as_ref().unwrap().ipv4, "10.44.0.1");
    assert_eq!(
        response.network_cidr.as_deref(),
        Some("10.44.0.0/24"),
        "注册响应必须携带生效段（Node 据此配置 TUN 路由）：{response:?}"
    );
    assert_eq!(
        response.dns_v4.as_deref(),
        Some("10.44.0.53"),
        "注册响应必须携带段内推导的 DNS 应答地址：{response:?}"
    );

    handle.shutdown();
    handle.terminated().await;

    // 未携带 flag 重开必须沿用 meta 固化的段。
    let reopened = Store::open_with_range(&db, RangeFlags::default())
        .await
        .unwrap();
    assert_eq!(reopened.addr().cidr.to_string(), "10.44.0.0/24");
}

#[tokio::test]
async fn range_change_is_rejected_once_nodes_exist() {
    let db = tmp_db("reject");
    let store = Store::open_with_range(&db, RangeFlags::default())
        .await
        .unwrap();
    let key = auth_key(&store).await;
    let (handle, mut client) = start(store).await;
    let registered = register_fresh(&mut client, &node_keys(), "node-a", &key).await;
    assert!(registered.is_ok());
    handle.shutdown();
    handle.terminated().await;

    let err = match Store::open_with_range(
        &db,
        RangeFlags {
            cidr: Some("10.55.0.0/24".to_string()),
            reserve: vec![],
        },
    )
    .await
    {
        Err(error) => format!("{error:#}"),
        Ok(_) => panic!("已有节点时改段必须被拒绝"),
    };
    assert!(err.contains("地址段"), "错误信息应点名地址段：{err}");
    assert!(
        err.contains("重新初始化") || err.contains("清库"),
        "错误信息应给出处置指引：{err}"
    );
}

#[tokio::test]
async fn range_change_is_adopted_while_db_has_no_nodes() {
    let db = tmp_db("adopt");
    let store = Store::open_with_range(&db, RangeFlags::default())
        .await
        .unwrap();
    assert_eq!(store.addr().cidr.to_string(), "100.96.0.0/16");
    drop(store);

    let reopened = Store::open_with_range(
        &db,
        RangeFlags {
            cidr: Some("10.55.0.0/24".to_string()),
            reserve: vec![],
        },
    )
    .await
    .unwrap();
    assert_eq!(reopened.addr().cidr.to_string(), "10.55.0.0/24");
    assert_eq!(
        reopened.addr().reserved_dns(),
        "10.55.0.53".parse::<std::net::Ipv4Addr>().unwrap()
    );
}

#[tokio::test]
async fn reserve_only_merges_with_stored_range_instead_of_implicit_re_range() {
    let db = tmp_db("reserve-only");
    let store = Store::open_with_range(
        &db,
        RangeFlags {
            cidr: Some("10.44.0.0/24".to_string()),
            reserve: vec![],
        },
    )
    .await
    .unwrap();
    drop(store);

    // 只给 --reserve：段必须仍是 10.44.0.0/24，而不是隐式回到默认段。
    let reopened = Store::open_with_range(
        &db,
        RangeFlags {
            cidr: None,
            reserve: vec!["10.44.0.9".parse().unwrap()],
        },
    )
    .await
    .unwrap();
    assert_eq!(reopened.addr().cidr.to_string(), "10.44.0.0/24");
    assert!(
        reopened
            .addr()
            .reserved
            .contains(&"10.44.0.9".parse().unwrap())
    );
}

#[tokio::test]
async fn reserve_outside_the_range_is_rejected() {
    let db = tmp_db("reserve-outside");
    let err = match Store::open_with_range(
        &db,
        RangeFlags {
            cidr: Some("10.44.0.0/24".to_string()),
            reserve: vec!["10.96.0.9".parse().unwrap()],
        },
    )
    .await
    {
        Err(error) => format!("{error:#}"),
        Ok(_) => panic!("段外保留地址必须被拒绝"),
    };
    assert!(
        err.contains("不在段"),
        "错误信息应指出保留地址不在段内：{err}"
    );
}

#[tokio::test]
async fn legacy_db_with_nodes_rejects_non_default_range() {
    let db = tmp_db("legacy");
    // 造一个"旧库"：正常初始化（固化默认段）后抹掉 addr_* meta，模拟升级前的库。
    let store = Store::open_with_range(&db, RangeFlags::default())
        .await
        .unwrap();
    let key = auth_key(&store).await;
    let (handle, mut client) = start(store).await;
    let registered = register_fresh(&mut client, &node_keys(), "node-a", &key).await;
    assert!(registered.is_ok());
    handle.shutdown();
    handle.terminated().await;
    // 直接清 meta（测试模拟旧版本库；生产中不存在 addr_* 行）。
    {
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", db.display()))
            .await
            .unwrap();
        sqlx::query("DELETE FROM meta WHERE key IN ('addr_cidr','addr_reserved')")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    let err = match Store::open_with_range(
        &db,
        RangeFlags {
            cidr: Some("10.55.0.0/24".to_string()),
            reserve: vec![],
        },
    )
    .await
    {
        Err(error) => format!("{error:#}"),
        Ok(_) => panic!("旧库已有 Node 时非默认段必须被拒绝"),
    };
    assert!(
        err.contains("默认段") && (err.contains("重新初始化") || err.contains("重新注册")),
        "错误信息应说明旧库节点来自默认段并给出处置指引：{err}"
    );
}
