//! Seam B：coord 存储 + relay 服务 + 两个 SocketEngine 走真实 TLS 中继。
//! 断言经 Relay 的双向互通、未注册/吊销/过期身份与错误 Relay Token 的拒绝。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use hz_coord::addr::AddressConfig;
use hz_coord::service::serve as serve_coord;
use hz_coord::service::{ServeConfig, ServeHandle};
use hz_coord::store::{NodeRecord, Store, unix_now};
use hz_core::keys::KeyStore;
use hz_core::relay_client::connect_relay;
use hz_core::wire::{PeerSpec, SocketEngine};
use hz_proto::relay_client::RelayClient as RelayGrpcClient;
use hz_proto::relay_frame;
use hz_proto::{RelayData, RelayFrame, RelayHello};
use hz_relay::tls;
use hz_relay::{RelayConfig, RelayHandle, serve_relay};
use rand_core::{OsRng, RngCore};
use tokio::sync::mpsc;
use tonic::Streaming;
use tonic::transport::Channel;

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

const RELAY_TIMEOUT: Duration = Duration::from_secs(20);

struct World {
    store: Store,
    relay_addr: SocketAddr,
    ca_pem: String,
    _coord: ServeHandle,
    relay: RelayHandle,
}

async fn spin_world(relay_token_override: Option<&str>) -> World {
    let store = Store::open_in_memory(AddressConfig::default())
        .await
        .unwrap();
    let token = store.create_relay_token().await.unwrap();

    let coord = serve_coord(ServeConfig::new(
        store.clone(),
        "127.0.0.1:0".parse().unwrap(),
    ))
    .await
    .unwrap();

    let tls::SelfSignedTls {
        server_config,
        ca_pem,
    } = tls::generate(&[]).unwrap();
    let relay = serve_relay(RelayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls: Some(server_config),
        coord_addr: format!("http://{}", coord.local_addr),
        relay_token: relay_token_override
            .map(str::to_owned)
            .unwrap_or_else(|| token.clone()),
    })
    .await
    .unwrap();

    World {
        store,
        relay_addr: relay.local_addr,
        ca_pem,
        _coord: coord,
        relay,
    }
}

struct Node {
    engine: Arc<SocketEngine>,
    to_tunnel: mpsc::Receiver<Vec<u8>>,
}

async fn register_node(store: &Store, state_dir: &Path, hostname: &str) -> NodeRecord {
    let keys = KeyStore::load_or_create(state_dir).unwrap();
    store
        .register_node(
            &keys.machine_public(),
            &keys.node_public(),
            hostname,
            &[],
            None,
            None,
        )
        .await
        .unwrap()
}

async fn spawn_node(state_dir: &Path, record: &NodeRecord, world: &World) -> Node {
    let keys = Arc::new(KeyStore::load_or_create(state_dir).unwrap());
    let engine = Arc::new(SocketEngine::bind(keys.node().clone(), 0).await.unwrap());
    let client = connect_relay(
        &keys,
        &record.id,
        &format!("https://{}", world.relay_addr),
        Some(&world.ca_pem),
    )
    .await
    .unwrap();
    engine.set_relay(Arc::new(client));
    let (to_tunnel_tx, to_tunnel) = mpsc::channel::<Vec<u8>>(256);
    let runner = engine.clone();
    tokio::spawn(async move {
        let _ = runner.run(to_tunnel_tx).await;
    });
    Node { engine, to_tunnel }
}

/// 对端 PeerSpec：Node Key 公钥取自注册记录（store 是唯一事实源）。
fn spec_for_peer(record: &NodeRecord) -> PeerSpec {
    PeerSpec {
        node_id: record.id.clone(),
        node_key_pub: record.node_key_pub.clone().try_into().unwrap(),
        endpoints: vec![],
        dst_addrs: vec![IpAddr::V4(record.ipv4), IpAddr::V6(record.ipv6)],
        use_relay: true,
    }
}

/// 合成的 UDP/IPv4 包（20 字节 IPv4 头 + 8 字节 UDP 头 + 载荷）。
fn udp_v4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2] = (total_len >> 8) as u8;
    packet[3] = total_len as u8;
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[20..22].copy_from_slice(&52000u16.to_be_bytes());
    packet[22..24].copy_from_slice(&51820u16.to_be_bytes());
    packet[24..26].copy_from_slice(&(8 + payload.len() as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    packet
}

/// 打开原始 RelayStream 并发出一个 hello，返回响应流与出站发送端
/// （供拒绝类断言复用：身份不通过时不得进入转发）。
async fn raw_hello_stream(
    machine: &SigningKey,
    node_id: &str,
    world: &World,
) -> anyhow::Result<(Streaming<RelayFrame>, mpsc::Sender<RelayFrame>)> {
    let channel = Channel::from_shared(format!("https://{}", world.relay_addr))
        .unwrap()
        .tls_config(tonic::transport::ClientTlsConfig::new().ca_certificate(
            tonic::transport::Certificate::from_pem(world.ca_pem.as_bytes()),
        ))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = RelayGrpcClient::new(channel);

    let node_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let hello = RelayHello {
        node_id: node_id.to_owned(),
        node_key_pub: x25519_dalek::PublicKey::from(&node_secret)
            .to_bytes()
            .to_vec(),
        machine_key_pub: machine.verifying_key().to_bytes().to_vec(),
        challenge_nonce: nonce.to_vec(),
        challenge_signature: machine.sign(&nonce).to_bytes().to_vec(),
    };
    let (frame_tx, frame_rx) = mpsc::channel::<RelayFrame>(4);
    frame_tx
        .send(RelayFrame {
            kind: Some(relay_frame::Kind::Hello(hello)),
        })
        .await
        .unwrap();
    let stream = client
        .relay_stream(tokio_stream::wrappers::ReceiverStream::new(frame_rx))
        .await?
        .into_inner();
    Ok((stream, frame_tx))
}

async fn next_error_frame(stream: &mut Streaming<RelayFrame>) -> (String, String) {
    let frame = tokio::time::timeout(RELAY_TIMEOUT, stream.message())
        .await
        .expect("响应帧必须及时到达")
        .expect("流不应在响应前关闭")
        .expect("流读取不应出错");
    match frame.kind {
        Some(relay_frame::Kind::Error(error)) => (error.code, error.message),
        other => panic!("期望 RelayError，实际 {other:?}"),
    }
}

#[tokio::test]
async fn relayed_ping_works_both_directions_over_tls() {
    init_logging();
    let world = spin_world(None).await;
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let record_a = register_node(&world.store, dir_a.path(), "relay-a").await;
    let record_b = register_node(&world.store, dir_b.path(), "relay-b").await;

    let mut node_a = spawn_node(dir_a.path(), &record_a, &world).await;
    let mut node_b = spawn_node(dir_b.path(), &record_b, &world).await;
    node_a.engine.reconcile(vec![spec_for_peer(&record_b)]);
    node_b.engine.reconcile(vec![spec_for_peer(&record_a)]);

    let a4 = record_a.ipv4;
    let b4 = record_b.ipv4;
    let packet_ab = udp_v4_packet(a4, b4, b"relay-ping-a-to-b");
    node_a.engine.send_ip_packet(&packet_ab).await;
    let got = tokio::time::timeout(RELAY_TIMEOUT, node_b.to_tunnel.recv())
        .await
        .expect("B 必须在超时前经 Relay 收到明文包")
        .expect("B 的隧道通道不应关闭");
    assert_eq!(got, packet_ab, "B 解出的明文必须逐字节等于 A 发出的包");

    let packet_ba = udp_v4_packet(b4, a4, b"relay-ping-b-to-a");
    node_b.engine.send_ip_packet(&packet_ba).await;
    let got = tokio::time::timeout(RELAY_TIMEOUT, node_a.to_tunnel.recv())
        .await
        .expect("A 必须在超时前经 Relay 收到明文包")
        .expect("A 的隧道通道不应关闭");
    assert_eq!(got, packet_ba, "A 解出的明文必须逐字节等于 B 发出的包");

    world.relay.shutdown();
    world.relay.terminated().await;
}

#[tokio::test]
async fn unregistered_machine_key_is_rejected_without_forwarding() {
    init_logging();
    let world = spin_world(None).await;
    let dir_a = tempfile::tempdir().unwrap();
    let record_a = register_node(&world.store, dir_a.path(), "legit-a").await;
    let mut node_a = spawn_node(dir_a.path(), &record_a, &world).await;
    node_a.engine.reconcile(vec![spec_for_peer(&record_a)]);

    let intruder = SigningKey::generate(&mut OsRng);
    let (mut stream, frame_tx) = raw_hello_stream(&intruder, "intruder", &world)
        .await
        .unwrap();
    let (code, message) = next_error_frame(&mut stream).await;
    assert_eq!(code, "unauthorized", "未注册身份必须收到拒绝帧");
    assert!(!message.is_empty(), "拒绝帧必须带原因");

    let send_after_reject = frame_tx
        .send(RelayFrame {
            kind: Some(relay_frame::Kind::Data(RelayData {
                dst_node_id: record_a.id.clone(),
                payload: b"must-not-forward".to_vec(),
            })),
        })
        .await;
    assert!(
        send_after_reject.is_err(),
        "拒绝后流必须已被 Relay 关闭，出站发送必须失败"
    );
    let leaked = tokio::time::timeout(Duration::from_millis(500), node_a.to_tunnel.recv()).await;
    assert!(leaked.is_err(), "被拒绝的流不得向任何已连接 Node 转发数据");

    world.relay.shutdown();
    world.relay.terminated().await;
}

#[tokio::test]
async fn revoked_and_expired_nodes_are_rejected() {
    init_logging();
    let world = spin_world(None).await;
    let dir_r = tempfile::tempdir().unwrap();
    let dir_e = tempfile::tempdir().unwrap();

    let revoked = register_node(&world.store, dir_r.path(), "revoked-node").await;
    world.store.revoke_node(&revoked.id).await.unwrap();
    let machine = KeyStore::load_or_create(dir_r.path())
        .unwrap()
        .machine()
        .clone();
    let (mut stream, _) = raw_hello_stream(&machine, &revoked.id, &world)
        .await
        .unwrap();
    let (code, message) = next_error_frame(&mut stream).await;
    assert_eq!(code, "unauthorized");
    assert_eq!(message, "Node 未注册或已吊销");

    let expired_keys = KeyStore::load_or_create(dir_e.path()).unwrap();
    let expired = world
        .store
        .register_node(
            &expired_keys.machine_public(),
            &expired_keys.node_public(),
            "expired-node",
            &[],
            None,
            Some(unix_now() - 10),
        )
        .await
        .unwrap();
    let (mut stream, _) = raw_hello_stream(expired_keys.machine(), &expired.id, &world)
        .await
        .unwrap();
    let (code, message) = next_error_frame(&mut stream).await;
    assert_eq!(code, "unauthorized");
    assert_eq!(message, "Node 已过期");

    world.relay.shutdown();
    world.relay.terminated().await;
}

#[tokio::test]
async fn wrong_relay_token_makes_coord_reject_every_check() {
    init_logging();
    let world = spin_world(Some("not-the-token")).await;
    let dir_a = tempfile::tempdir().unwrap();
    let record_a = register_node(&world.store, dir_a.path(), "token-test-node").await;

    let machine = KeyStore::load_or_create(dir_a.path())
        .unwrap()
        .machine()
        .clone();
    let (mut stream, _) = raw_hello_stream(&machine, &record_a.id, &world)
        .await
        .unwrap();
    let (code, message) = next_error_frame(&mut stream).await;
    assert_eq!(code, "unauthorized");
    assert_eq!(
        message, "Relay Token 无效",
        "Coordination 侧必须因令牌不符拒绝"
    );

    world.relay.shutdown();
    world.relay.terminated().await;
}
