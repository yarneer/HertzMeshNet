//! 数据面引擎的纯逻辑测试：两个 Engine 直连模拟 UDP，不碰 socket 与 TUN。
//! WireGuard 握手是确定性的四步：发起、响应、排空排队包、解出明文。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hz_core::wire::{Engine, EngineOutput, PeerSpec};

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
use rand_core::OsRng;
use x25519_dalek::{PublicKey as NodePublicKey, StaticSecret as NodeStaticSecret};

const A_UDP: &str = "192.168.1.1:51820";
const B_UDP: &str = "192.168.1.2:51820";

const MSG_HANDSHAKE_INIT: u8 = 1;
const MSG_HANDSHAKE_RESPONSE: u8 = 2;
const MSG_DATA: u8 = 4;

struct TestNode {
    secret: NodeStaticSecret,
    public: [u8; 32],
    v4: Ipv4Addr,
    v6: Ipv6Addr,
    udp: SocketAddr,
}

fn test_node(v4: &str, v6: &str, udp: &str) -> TestNode {
    let secret = NodeStaticSecret::random_from_rng(OsRng);
    let public = NodePublicKey::from(&secret).to_bytes();
    TestNode {
        secret,
        public,
        v4: v4.parse().unwrap(),
        v6: v6.parse().unwrap(),
        udp: udp.parse().unwrap(),
    }
}

fn spec_for(peer: &TestNode) -> PeerSpec {
    PeerSpec {
        node_id: peer_name(peer).to_string(),
        node_key_pub: peer.public,
        endpoints: vec![peer.udp],
        dst_addrs: vec![IpAddr::V4(peer.v4), IpAddr::V6(peer.v6)],
        use_relay: false,
    }
}

fn relay_spec_for(peer: &TestNode) -> PeerSpec {
    PeerSpec {
        use_relay: true,
        ..spec_for(peer)
    }
}

fn peer_name(peer: &TestNode) -> &'static str {
    match peer.udp.port() {
        51820 => "node-a",
        _ => "node-b",
    }
}

/// 把一份输出里的全部数据报投递给目标引擎，返回其全部输出。
fn deliver(out: &EngineOutput, target: &mut Engine, source_udp: SocketAddr) -> EngineOutput {
    let mut combined = EngineOutput::default();
    for send in &out.to_network {
        let received = target.handle_udp(source_udp, &send.datagram);
        combined.to_tunnel.extend(received.to_tunnel);
        combined.to_network.extend(received.to_network);
    }
    combined
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

/// 合成的 UDP/IPv6 包（40 字节 IPv6 头 + 8 字节 UDP 头 + 载荷）。
fn udp_v6_packet(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let total_len = 8 + payload.len();
    let mut packet = vec![0u8; 40 + total_len];
    packet[0] = 0x60;
    packet[4] = (total_len >> 8) as u8;
    packet[5] = total_len as u8;
    packet[6] = 17;
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());
    packet[40..42].copy_from_slice(&52000u16.to_be_bytes());
    packet[42..44].copy_from_slice(&51820u16.to_be_bytes());
    packet[44..46].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[48..].copy_from_slice(payload);
    packet
}

fn wired_pair() -> (TestNode, TestNode, Engine, Engine) {
    let a = test_node("100.96.0.1", "fd12:3456:789a::6460:1", A_UDP);
    let b = test_node("100.96.0.2", "fd12:3456:789a::6460:2", B_UDP);
    let mut engine_a = Engine::new(a.secret.clone());
    let mut engine_b = Engine::new(b.secret.clone());
    engine_a.configure(spec_for(&b));
    engine_b.configure(spec_for(&a));
    (a, b, engine_a, engine_b)
}

#[test]
fn two_engines_exchange_v4_and_v6_packets_end_to_end() {
    init_logging();
    let (a, b, mut engine_a, mut engine_b) = wired_pair();
    let v4_packet = udp_v4_packet(a.v4, b.v4, b"hertz-mesh-v4");
    let v6_packet = udp_v6_packet(a.v6, b.v6, b"hertz-mesh-v6");

    let init = engine_a.send_ip_packet(&v4_packet);
    assert_eq!(init.to_network.len(), 1, "首包必须恰好产生一个握手发起包");
    assert_eq!(init.to_network[0].datagram[0], MSG_HANDSHAKE_INIT);
    assert_eq!(init.to_network[0].primary, b.udp);
    assert!(init.to_tunnel.is_empty());

    let response = deliver(&init, &mut engine_b, a.udp);
    assert_eq!(response.to_network.len(), 1, "B 必须恰好回应一个握手响应");
    assert_eq!(response.to_network[0].datagram[0], MSG_HANDSHAKE_RESPONSE);
    assert!(response.to_tunnel.is_empty());

    let flushed = deliver(&response, &mut engine_a, b.udp);
    assert!(
        !flushed.to_network.is_empty(),
        "握手完成后 A 必须补发排队的原始包"
    );
    assert!(
        flushed
            .to_network
            .iter()
            .all(|send| send.datagram[0] == MSG_DATA),
        "补发的必须是加密数据包"
    );

    let decrypted = deliver(&flushed, &mut engine_b, a.udp);
    assert_eq!(decrypted.to_tunnel, vec![v4_packet.clone()]);
    assert!(decrypted.to_network.is_empty());

    let v6_out = engine_a.send_ip_packet(&v6_packet);
    assert_eq!(v6_out.to_network.len(), 1);
    assert_eq!(
        v6_out.to_network[0].datagram[0], MSG_DATA,
        "v6 包应走既有会话"
    );
    let v6_decrypted = deliver(&v6_out, &mut engine_b, a.udp);
    assert_eq!(v6_decrypted.to_tunnel, vec![v6_packet]);
}

#[test]
fn unanswered_handshake_is_retransmitted_and_still_completes() {
    let (a, b, mut engine_a, mut engine_b) = wired_pair();
    let packet = udp_v4_packet(a.v4, b.v4, b"retry-me");

    let init = engine_a.send_ip_packet(&packet);
    assert_eq!(init.to_network.len(), 1);
    // 模拟发起包丢失：不投递。定时器必须在 boringtun 的重握手窗口内重发。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut retransmit = None;
    while retransmit.is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let out = engine_a.tick();
        if let Some(send) = out.to_network.first() {
            retransmit = Some(send.datagram.clone());
        }
    }
    let retransmit = retransmit.expect("未应答的握手必须在 20 秒内由定时器重传");

    let response = deliver(
        &EngineOutput {
            to_network: vec![hz_core::wire::NetworkSend {
                node_id: "node-b".to_string(),
                primary: b.udp,
                alternates: vec![],
                datagram: retransmit,
            }],
            to_relay: vec![],
            to_tunnel: vec![],
        },
        &mut engine_b,
        a.udp,
    );
    assert_eq!(response.to_network.len(), 1, "B 必须回应重传的发起包");
    let flushed = deliver(&response, &mut engine_a, b.udp);
    let decrypted = deliver(&flushed, &mut engine_b, a.udp);
    assert_eq!(decrypted.to_tunnel, vec![packet], "重传握手后链路必须打通");
}

#[test]
fn packet_to_unknown_destination_is_dropped_silently() {
    let (_a, _b, mut engine_a, _engine_b) = wired_pair();
    let stranger: Ipv4Addr = "100.96.9.9".parse().unwrap();
    let out = engine_a.send_ip_packet(&udp_v4_packet(
        "100.96.0.1".parse().unwrap(),
        stranger,
        b"nobody-home",
    ));
    assert!(out.to_network.is_empty(), "未知目的地址不得产生任何数据报");
    assert!(out.to_tunnel.is_empty());
}

#[test]
fn handshake_from_wrong_peer_key_never_decodes() {
    let (a, b, mut engine_a, mut engine_b) = wired_pair();
    // B 认为 A 的 Node Key 是第三方的公钥，A 发来的握手永远解不开。
    let mut impostor = test_node("100.96.0.1", "fd12:3456:789a::6460:1", A_UDP);
    impostor.secret = NodeStaticSecret::random_from_rng(OsRng);
    impostor.public = NodePublicKey::from(&impostor.secret).to_bytes();
    engine_b.configure(spec_for(&impostor));

    let packet = udp_v4_packet(a.v4, b.v4, b"should-never-arrive");
    let mut out = engine_a.send_ip_packet(&packet);
    for round in 0..3 {
        let received = deliver(&out, &mut engine_b, a.udp);
        assert!(received.to_tunnel.is_empty(), "密钥不匹配时不得解出明文");
        assert!(
            received.to_network.is_empty(),
            "B 不认识对端时不得产生响应（第 {round} 轮）"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            out = engine_a.tick();
            if !out.to_network.is_empty() || std::time::Instant::now() > deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        assert!(!out.to_network.is_empty(), "A 应继续重试握手");
    }
}

/// 经内存中继通道交付：模拟 Relay 只按 node id 转发、观测不到明文的最小形态。
/// 返回中继侧全程观测到的全部密文字节。
fn deliver_over_relay(
    out: &EngineOutput,
    target: &mut Engine,
    observed: &mut Vec<Vec<u8>>,
) -> EngineOutput {
    let mut combined = EngineOutput::default();
    for send in &out.to_relay {
        observed.push(send.datagram.clone());
        let received = target.handle_relay_datagram(&send.datagram);
        combined.to_tunnel.extend(received.to_tunnel);
        combined.to_relay.extend(received.to_relay);
    }
    combined
}

fn relay_wired_pair() -> (TestNode, TestNode, Engine, Engine) {
    let a = test_node("100.96.0.1", "fd12:3456:789a::6460:1", A_UDP);
    let b = test_node("100.96.0.2", "fd12:3456:789a::6460:2", B_UDP);
    let mut engine_a = Engine::new(a.secret.clone());
    let mut engine_b = Engine::new(b.secret.clone());
    engine_a.configure(relay_spec_for(&b));
    engine_b.configure(relay_spec_for(&a));
    (a, b, engine_a, engine_b)
}

#[test]
fn relayed_exchange_reaches_peer_and_hides_plaintext_from_relay() {
    init_logging();
    let (a, b, mut engine_a, mut engine_b) = relay_wired_pair();
    let payload = b"hzmesh-relay-secret-payload";
    let packet = udp_v4_packet(a.v4, b.v4, payload);

    let init = engine_a.send_ip_packet(&packet);
    assert_eq!(init.to_relay.len(), 1, "Relay 对端的首包应产生一个中继数据报");
    assert!(init.to_network.is_empty(), "开关指向 Relay 时不得走直连 UDP");

    let mut observed: Vec<Vec<u8>> = Vec::new();
    let response = deliver_over_relay(&init, &mut engine_b, &mut observed);
    assert_eq!(response.to_relay.len(), 1, "B 必须恰好回应一个握手响应");
    assert_eq!(response.to_relay[0].node_id, "node-a");

    let flushed = deliver_over_relay(&response, &mut engine_a, &mut observed);
    assert!(
        !flushed.to_relay.is_empty(),
        "握手完成后 A 必须补发排队的原始包"
    );

    let decrypted = deliver_over_relay(&flushed, &mut engine_b, &mut observed);
    assert_eq!(decrypted.to_tunnel, vec![packet.clone()], "中继链路必须打通");
    assert!(decrypted.to_relay.is_empty());

    // Relay 全程只看到 WireGuard 密文：既不含明文字面量，也比明文载荷长。
    assert!(!observed.is_empty());
    for (round, bytes) in observed.iter().enumerate() {
        assert!(
            !bytes
                .windows(payload.len())
                .any(|window| window == payload),
            "第 {round} 个中继数据报泄漏了明文载荷"
        );
        assert!(
            bytes.len() > payload.len(),
            "第 {round} 个中继数据报短于明文载荷，不可能是 WireGuard 密文"
        );
    }
}

#[test]
fn relay_datagram_for_unknown_index_is_dropped_silently() {
    let (_a, _b, mut engine_a, _engine_b) = relay_wired_pair();
    let mut stranger_datagram = vec![MSG_DATA; 64];
    stranger_datagram[4..8].copy_from_slice(&0xdead_beefu32.to_le_bytes());
    let out = engine_a.handle_relay_datagram(&stranger_datagram);
    assert!(out.to_tunnel.is_empty());
    assert!(out.to_relay.is_empty());
}
