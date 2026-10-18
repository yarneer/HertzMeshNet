//! `hz ping` 探针的数据面行为（FR-12）：两个 SocketEngine 经真实 UDP socket
//! 直连，探针请求由 A 的引擎封装发出，B 侧在"进 TUN 前"的拦截点应答，
//! 应答回到 A 侧的等待方。往返走完整 WireGuard 加密路径。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hz_core::wire::{PeerSpec, SocketEngine};
use hzd::ping;
use rand_core::OsRng;
use rand_core::RngCore;
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey as NodePublicKey, StaticSecret as NodeStaticSecret};

const A_V4: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 1);
const B_V4: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 2);

struct Side {
    engine: Arc<SocketEngine>,
    secret: NodeStaticSecret,
    v4: Ipv4Addr,
    v6: Ipv6Addr,
}

async fn side(v4: Ipv4Addr, v6: &str) -> Side {
    let secret = NodeStaticSecret::random_from_rng(OsRng);
    // 对端 Endpoint 在回环上，SO_BINDTODEVICE 到物理出口会挡掉收发：
    // 与 HZD_BIND_EGRESS=0 的开发路径一致，跳过出口绑定。
    let engine = SocketEngine::bind_with(secret.clone(), 0, false)
        .await
        .unwrap();
    Side {
        engine: Arc::new(engine),
        secret,
        v4,
        v6: v6.parse().unwrap(),
    }
}

fn spec_for(peer: &Side, node_id: &str) -> PeerSpec {
    PeerSpec {
        node_id: node_id.to_owned(),
        node_key_pub: NodePublicKey::from(&peer.secret).to_bytes(),
        // 双栈绑定的 local_addr 是未指定的 [::]:port；v6 socket 发往 v4
        // 目标必须用 v4-mapped 形式（::ffff:127.0.0.1）。
        endpoints: vec![SocketAddr::new(
            IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
            peer.engine.local_addr().port(),
        )],
        dst_addrs: vec![IpAddr::V4(peer.v4), IpAddr::V6(peer.v6)],
        use_relay: false,
    }
}

/// 消费解密包：先过探针拦截，其余丢弃（本测试不挂 TUN）。
fn spawn_sink(engine: Arc<SocketEngine>, probes: Arc<ping::Probes>, own_v4: Ipv4Addr) {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    let runner = engine.clone();
    tokio::spawn(async move {
        let _ = runner.run(tx).await;
    });
    tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            if ping::intercept(&engine, &probes, own_v4, &packet).await {
                continue;
            }
        }
    });
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_measures_round_trip_over_wireguard_path() {
    init_logging();
    let a = side(A_V4, "fd12:3456:789a::6460:1").await;
    let b = side(B_V4, "fd12:3456:789a::6460:2").await;
    a.engine.reconcile(vec![spec_for(&b, "node-b")]);
    b.engine.reconcile(vec![spec_for(&a, "node-a")]);

    let probes_a = Arc::new(ping::Probes::default());
    let probes_b = Arc::new(ping::Probes::default());
    spawn_sink(a.engine.clone(), probes_a.clone(), A_V4);
    spawn_sink(b.engine.clone(), probes_b, B_V4);

    let mut measured = None;
    for _ in 0..5 {
        let nonce = OsRng.next_u64();
        let done = probes_a.spawn(nonce);
        let sent = Instant::now();
        a.engine
            .send_ip_packet(&ping::build(A_V4, B_V4, false, nonce))
            .await;
        if let Ok(Ok(())) = tokio::time::timeout(Duration::from_secs(3), done).await {
            measured = Some(sent.elapsed());
            break;
        }
    }
    let rtt = measured.expect("探针必须在若干次尝试内完成往返（首次可能被冷握手吃掉）");
    assert!(rtt > Duration::ZERO && rtt < Duration::from_secs(3));

    let report = a
        .engine
        .peer_reports()
        .into_iter()
        .find(|report| report.node_id == "node-b")
        .expect("对端必须有数据面报告");
    assert!(!report.use_relay, "直连场景下路径报告必须是 Direct");
    assert!(report.handshake_age.is_some(), "探针往返意味着握手已完成");
}
