//! Network Map 下发的服务端契约（真实 tonic over loopback + 内存 SQLite）：
//! 挑战认证、Endpoint 落库、全量快照内容、未注册/坏签名拒绝、周期性重发。

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
use tonic::Status;
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

async fn start_server(map_refresh: Duration) -> (ServeHandle, Store, SocketAddr) {
    let store = Store::open_in_memory(AddressConfig::default())
        .await
        .unwrap();
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut config = ServeConfig::new(store.pool().clone(), listen);
    config.map_refresh = map_refresh;
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

async fn open_map(
    client: &mut CoordClient<Channel>,
    keys: &NodeKeys,
    endpoints: Vec<String>,
    signature_override: Option<[u8; 64]>,
) -> Result<tonic::Response<tonic::codec::Streaming<hz_proto::NetworkMapMessage>>, Status> {
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
}

#[tokio::test]
async fn map_stream_authenticates_upserts_endpoints_and_delivers_full_snapshot() {
    let (handle, store, addr) = start_server(Duration::from_secs(3600)).await;
    let auth_key = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, false, &[])
        .await
        .unwrap();

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
    .unwrap()
    .into_inner();

    let message = tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
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
async fn map_stream_is_periodically_resent_as_keepalive() {
    let (handle, store, addr) = start_server(Duration::from_millis(200)).await;
    let mut client = connect(addr).await;

    let node = node_keys();
    let auth_key = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, false, &[])
        .await
        .unwrap();
    let _info = register(&mut client, &node, "keeper", &auth_key).await;

    let mut stream = open_map(&mut client, &node, vec![], None)
        .await
        .unwrap()
        .into_inner();
    for expected in 1..=2 {
        let message = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .unwrap_or_else(|_| panic!("第 {expected} 份快照应在 5 秒内到达（周期性重发）"))
            .unwrap()
            .unwrap();
        assert!(matches!(message.kind, Some(Kind::Full(_))));
    }

    handle.shutdown();
    handle.terminated().await;
}

#[tokio::test]
async fn map_stream_rejects_bad_signature_and_unregistered_keys() {
    let (handle, store, addr) = start_server(Duration::from_secs(3600)).await;
    let mut client = connect(addr).await;

    let stranger = node_keys();
    let status = open_map(&mut client, &stranger, vec![], None)
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status}");

    let node = node_keys();
    let auth_key = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, false, &[])
        .await
        .unwrap();
    let _info = register(&mut client, &node, "signed-node", &auth_key).await;
    let bad_signature = SigningKey::generate(&mut OsRng).sign(b"nonce").to_bytes();
    let status = open_map(&mut client, &node, vec![], Some(bad_signature))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unauthenticated, "{status}");

    handle.shutdown();
    handle.terminated().await;
}
