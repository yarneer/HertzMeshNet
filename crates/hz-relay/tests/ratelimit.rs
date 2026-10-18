//! Seam B：限速与指标（issue #15）。两个真实注册的 Node 经原始 RelayStream
//! 对发数据帧，断言发送方预算被入口限速执行（超额帧被丢）、被投递的帧在
//! /metrics 上按 Node 可见、丢弃字节与在线会话数可抓取。

use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::Signer;
use hz_coord::addr::AddressConfig;
use hz_coord::service::ServeConfig;
use hz_coord::service::serve as serve_coord;
use hz_coord::store::Store;
use hz_core::keys::KeyStore;
use hz_proto::relay_client::RelayClient as RelayGrpcClient;
use hz_proto::relay_frame;
use hz_proto::{RelayData, RelayFrame, RelayHello};
use hz_relay::tls;
use hz_relay::{RelayConfig, serve_relay};
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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

const FRAME: usize = 20_000;
const FRAMES: usize = 30;

struct World {
    relay_addr: SocketAddr,
    metrics_addr: SocketAddr,
    ca_pem: String,
}

async fn spin_world(rate_limit_mbps: u64) -> (Store, World) {
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
        relay_token: token,
        rate_limit_mbps,
        metrics_listen: Some("127.0.0.1:0".parse().unwrap()),
    })
    .await
    .unwrap();
    let metrics_addr = relay
        .metrics_addr()
        .expect("配置了 metrics_listen 就必须有监听地址");
    let relay_addr = relay.local_addr;
    tokio::spawn(async move {
        coord.terminated().await;
        let _ = relay.terminated().await;
    });
    let world = World {
        relay_addr,
        metrics_addr,
        ca_pem,
    };
    (store, world)
}

async fn open_session(
    keys: &KeyStore,
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
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let hello = RelayHello {
        node_id: node_id.to_owned(),
        node_key_pub: keys.node_public().to_vec(),
        machine_key_pub: keys.machine_public().to_vec(),
        challenge_nonce: nonce.to_vec(),
        challenge_signature: keys.machine().sign(&nonce).to_bytes().to_vec(),
    };
    let (frame_tx, frame_rx) = mpsc::channel::<RelayFrame>(FRAMES + 2);
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

/// 极简 HTTP/1.1 GET：返回整个响应文本（含头）。
async fn scrape(addr: SocketAddr) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await.unwrap();
    String::from_utf8_lossy(&body).into_owned()
}

fn counter_value(text: &str, prefix: &str, node_id: &str) -> Option<u64> {
    for line in text.lines() {
        if line.starts_with(prefix) && line.contains(&format!("node_id=\"{node_id}\"")) {
            return line.rsplit(' ').next()?.parse().ok();
        }
    }
    None
}

#[tokio::test]
async fn rate_limit_policing_and_metrics_are_observable() {
    init_logging();
    // 1 Mbps：桶容量 125_000 B。30 × 20_000 B = 600_000 B 一口气灌入，
    // 只有桶内（加上微秒级补充）能通过，其余必须被丢弃。
    let (store, world) = spin_world(1).await;
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let keys_a = KeyStore::load_or_create(dir_a.path()).unwrap();
    let keys_b = KeyStore::load_or_create(dir_b.path()).unwrap();
    let record_a = store
        .register_node(
            &keys_a.machine_public(),
            &keys_a.node_public(),
            "meter-a",
            &[],
            None,
            None,
        )
        .await
        .unwrap();
    let record_b = store
        .register_node(
            &keys_b.machine_public(),
            &keys_b.node_public(),
            "meter-b",
            &[],
            None,
            None,
        )
        .await
        .unwrap();

    let (mut stream_b, _tx_b) = open_session(&keys_b, &record_b.id, &world).await.unwrap();
    let (mut stream_a, tx_a) = open_session(&keys_a, &record_a.id, &world).await.unwrap();
    // 会话登记是异步的：等 A 的首帧（B 未发数据，用短路探测确认双会话在线）。
    tokio::time::sleep(Duration::from_millis(300)).await;

    for _ in 0..FRAMES {
        tx_a.send(data_frame(&record_b.id, FRAME)).await.unwrap();
    }
    // 不关 A 的流：两条会话保持在线，等转发与限速处理完成后抓取指标。
    tokio::time::sleep(Duration::from_millis(500)).await;

    let text = scrape(world.metrics_addr).await;
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "响应头：{}",
        &text[..40.min(text.len())]
    );
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or("");
    let admitted = counter_value(
        body,
        "hz_relay_node_bytes_total{direction=\"in\"",
        &record_a.id,
    )
    .expect("metrics 必须包含发送方 in 计数");
    let out = counter_value(
        body,
        "hz_relay_node_bytes_total{direction=\"out\"",
        &record_b.id,
    )
    .expect("metrics 必须包含接收方 out 计数");
    let dropped = counter_value(body, "hz_relay_dropped_bytes_total", &record_a.id)
        .expect("metrics 必须包含丢弃计数");
    assert_eq!(
        admitted + dropped,
        (FRAMES * FRAME) as u64,
        "in + dropped 必须守恒等于发送总量"
    );
    assert!(dropped > 0, "超限帧必须被丢弃并计数");
    assert!(
        (2 * FRAME as u64..=7 * FRAME as u64).contains(&admitted),
        "放行字节 {admitted} 应在桶容量（125_000 B，6 帧）附近，既不饿死也不超发"
    );
    assert!(
        body.contains("hz_relay_sessions 2"),
        "两条会话应同时在线，实际：\n{body}"
    );

    drop(tx_a);
    let mut delivered = 0usize;
    while let Ok(Ok(Some(frame))) =
        tokio::time::timeout(Duration::from_secs(2), stream_b.message()).await
    {
        if let Some(relay_frame::Kind::Data(data)) = frame.kind {
            assert_eq!(data.payload.len(), FRAME);
            delivered += FRAME;
        }
    }
    assert_eq!(
        delivered as u64, out,
        "实际收到的字节必须与 metrics 的 out 计数一致"
    );
    let _ = stream_a.message().await;
}

fn data_frame(dst: &str, len: usize) -> RelayFrame {
    RelayFrame {
        kind: Some(relay_frame::Kind::Data(RelayData {
            dst_node_id: dst.to_owned(),
            payload: vec![0x5a; len],
        })),
    }
}
