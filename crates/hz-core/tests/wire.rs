//! 数据面引擎的纯逻辑测试：两个 Engine 直连模拟 UDP，不碰 socket 与 TUN。
//! WireGuard 握手是确定性的四步：发起、响应、排空排队包、解出明文。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

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
    assert_eq!(
        init.to_relay.len(),
        1,
        "Relay 对端的首包应产生一个中继数据报"
    );
    assert!(
        init.to_network.is_empty(),
        "开关指向 Relay 时不得走直连 UDP"
    );

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
    assert_eq!(
        decrypted.to_tunnel,
        vec![packet.clone()],
        "中继链路必须打通"
    );
    assert!(decrypted.to_relay.is_empty());

    // Relay 全程只看到 WireGuard 密文：既不含明文字面量，也比明文载荷长。
    assert!(!observed.is_empty());
    for (round, bytes) in observed.iter().enumerate() {
        assert!(
            !bytes.windows(payload.len()).any(|window| window == payload),
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

#[test]
fn punch_handshake_yields_init_but_never_resets_in_flight_exchange() {
    let (a, b, mut engine_a, mut engine_b) = wired_pair();
    // 先走完整握手拿到稳定会话（Relay 场景的常态），再验证打洞行为。
    let packet = udp_v4_packet(a.v4, b.v4, b"session-first");
    let init = engine_a.send_ip_packet(&packet);
    let response = deliver(&init, &mut engine_b, a.udp);
    let flushed = deliver(&response, &mut engine_a, b.udp);
    let _ = deliver(&flushed, &mut engine_b, a.udp);

    let datagram = engine_a
        .punch_handshake(peer_name(&b))
        .expect("会话存续且无进行中握手时，打洞必须能发出握手发起包");
    assert_eq!(datagram[0], MSG_HANDSHAKE_INIT);
    // 打洞占用握手槽位后立即再打洞必须让位：返回 None 而不是强制重置，
    // 否则正在进行的握手交换（如 Relay 侧）会被反复打断、永远无法完成。
    assert!(engine_a.punch_handshake(peer_name(&b)).is_none());
    // 打洞产生的发起包仍是合法 WireGuard 报文，对端能应答。
    let out = engine_a.handle_udp(b.udp, &datagram);
    let _ = out;
    assert!(engine_a.punch_handshake("stranger").is_none());
    let response = engine_b.handle_udp(a.udp, &datagram);
    assert_eq!(response.to_network.len(), 1, "对端必须回应打洞握手");
    assert_eq!(response.to_network[0].datagram[0], MSG_HANDSHAKE_RESPONSE);
}

#[test]
fn direct_rx_age_tracks_udp_reception_only() {
    let (a, b, mut engine_a, mut engine_b) = wired_pair();
    let name = peer_name(&a);
    assert!(
        engine_b
            .direct_rx_ages()
            .get(name)
            .copied()
            .flatten()
            .is_none(),
        "未收到任何直连报文前 direct_rx 必须为 None"
    );

    let init = engine_a.send_ip_packet(&udp_v4_packet(a.v4, b.v4, b"hello"));
    let response = deliver(&init, &mut engine_b, a.udp);
    assert!(
        engine_b
            .direct_rx_ages()
            .get(name)
            .copied()
            .flatten()
            .is_none(),
        "仅收到握手发起包不算直连存活：对端安全组丢弃入方向时仍会发出发起包"
    );
    let flushed = deliver(&response, &mut engine_a, b.udp);
    let _ = deliver(&flushed, &mut engine_b, a.udp);
    let age = engine_b
        .direct_rx_ages()
        .get(name)
        .copied()
        .flatten()
        .expect("握手完成后的传输报文必须点亮 direct_rx");
    assert!(age < Duration::from_secs(5));

    // 伪造对端身份的报文解不开，不应点亮 direct_rx。
    let intruder = test_node("100.96.0.9", "fd12:3456:789a::6460:9", "192.168.1.9:51820");
    let mut engine_intruder = Engine::new(intruder.secret.clone());
    engine_intruder.configure(spec_for(&b));
    let bogus = engine_intruder.send_ip_packet(&udp_v4_packet(intruder.v4, b.v4, b"spoof"));
    let _ = deliver(&bogus, &mut engine_b, intruder.udp);
    let still = engine_b
        .direct_rx_ages()
        .get(name)
        .copied()
        .flatten()
        .expect("合法记录不被伪造报文清除");
    assert!(still >= age);
}

#[test]
fn set_use_relay_switches_outbound_dispatch_per_peer() {
    let (a, b, mut engine_a, mut engine_b) = wired_pair();
    let name = peer_name(&b);
    let packet = udp_v4_packet(a.v4, b.v4, b"switch-me");

    // 先完成完整握手，得到稳定会话后再验证开关（无会话时首包只触发握手，
    // 不构成对开关的判别）。
    let init = engine_a.send_ip_packet(&packet);
    let response = deliver(&init, &mut engine_b, a.udp);
    let flushed = deliver(&response, &mut engine_a, b.udp);
    let _ = deliver(&flushed, &mut engine_b, a.udp);

    let direct = engine_a.send_ip_packet(&packet);
    assert_eq!(direct.to_network.len(), 1, "直连开关下出向走 UDP");
    assert!(direct.to_relay.is_empty());

    engine_a.set_use_relay(name, true);
    let relayed = engine_a.send_ip_packet(&packet);
    assert!(
        relayed.to_network.is_empty(),
        "开关切 Relay 后出向必须走 Relay"
    );
    assert_eq!(relayed.to_relay.len(), 1);
    assert_eq!(relayed.to_relay[0].node_id, name);

    engine_a.set_use_relay(name, false);
    let back = engine_a.send_ip_packet(&packet);
    assert_eq!(back.to_network.len(), 1, "切回直连后出向恢复 UDP");
    assert!(back.to_relay.is_empty());
}

#[test]
fn peer_reports_expose_path_endpoint_and_handshake_state() {
    let (a, b, mut engine_a, mut engine_b) = wired_pair();
    let before = engine_a
        .peer_reports()
        .into_iter()
        .find(|report| report.node_id == peer_name(&b))
        .unwrap();
    assert!(
        !before.use_relay && before.endpoint == Some(b.udp),
        "直连对端应在报告中给出在用 Endpoint"
    );
    assert_eq!(before.handshake_age, None, "握手前无最近握手时间");

    let init = engine_a.send_ip_packet(&udp_v4_packet(a.v4, b.v4, b"report-me"));
    let response = deliver(&init, &mut engine_b, a.udp);
    let flushed = deliver(&response, &mut engine_a, b.udp);
    let _ = deliver(&flushed, &mut engine_b, a.udp);

    let after = engine_a
        .peer_reports()
        .into_iter()
        .find(|report| report.node_id == peer_name(&b))
        .unwrap();
    let age = after.handshake_age.expect("握手完成后必须有最近握手时间");
    assert!(
        age < Duration::from_secs(1),
        "刚完成的握手应记为刚刚：{age:?}"
    );

    engine_a.set_use_relay(peer_name(&b), true);
    let relayed = engine_a
        .peer_reports()
        .into_iter()
        .find(|report| report.node_id == peer_name(&b))
        .unwrap();
    assert!(relayed.use_relay, "开关切 Relay 后报告路径为 Relayed");
    assert_eq!(relayed.endpoint, None, "Relayed 时没有在用的对端 Endpoint");
    assert!(relayed.handshake_age.is_some());
}

#[test]
fn own_key_rotation_drops_sessions_and_rejoins_with_new_key() {
    let (a, b, mut engine_a, mut engine_b) = wired_pair();

    let packet = udp_v4_packet(a.v4, b.v4, b"before-rotation");
    let init = engine_a.send_ip_packet(&packet);
    let response = deliver(&init, &mut engine_b, a.udp);
    let flushed = deliver(&response, &mut engine_a, b.udp);
    let decrypted = deliver(&flushed, &mut engine_b, a.udp);
    assert_eq!(
        decrypted.to_tunnel,
        vec![packet.clone()],
        "轮换前两端必须已经互通"
    );

    let fresh = NodeStaticSecret::random_from_rng(OsRng);
    let fresh_public = NodePublicKey::from(&fresh).to_bytes();
    engine_a.rotate_own_key(fresh);
    assert_eq!(
        engine_a.peer_count(),
        0,
        "轮换后旧密钥建立的会话必须全部作废"
    );

    // 对端按新公钥重建（coord 下发的 node_key_pub 变化），本机重放对账。
    engine_b.configure(PeerSpec {
        node_key_pub: fresh_public,
        ..spec_for(&a)
    });
    engine_a.reconcile(vec![spec_for(&b)]);

    let after = udp_v4_packet(a.v4, b.v4, b"after-rotation");
    let init2 = engine_a.send_ip_packet(&after);
    assert_eq!(init2.to_network.len(), 1, "轮换后首个出站包必须重新握手");
    let response2 = deliver(&init2, &mut engine_b, a.udp);
    let flushed2 = deliver(&response2, &mut engine_a, b.udp);
    let decrypted2 = deliver(&flushed2, &mut engine_b, a.udp);
    assert_eq!(
        decrypted2.to_tunnel,
        vec![after],
        "新密钥下通信必须恢复，旧密钥会话不再续命"
    );
}

/// 显式 node_id 的对端描述：绕开 peer_name 的端口推断，测试里同引擎容纳多个对端。
fn named_spec(node_id: &str, peer: &TestNode) -> PeerSpec {
    PeerSpec {
        node_id: node_id.to_string(),
        ..spec_for(peer)
    }
}

#[test]
fn handshake_completes_when_peers_number_tunnels_differently() {
    // 两侧给对方分配的本地隧道序号不同（B 先配了另一个对端，A 在 B 那里是第二个）。
    // 握手响应的 [4..8] 是响应方的发送索引、[8..12] 才是回显给发起方的接收索引；
    // 按前者寻位时，只有两侧序号空间碰巧重叠才能完成握手（#11 到期重登后的死链）。
    let a = test_node("100.96.0.1", "fd12:3456:789a::6460:1", "192.168.1.1:51820");
    let b = test_node("100.96.0.2", "fd12:3456:789a::6460:2", "192.168.1.2:51820");
    let first_on_b = test_node("100.96.0.9", "fd12:3456:789a::6460:9", "192.168.1.9:51820");
    let mut engine_a = Engine::new(a.secret.clone());
    let mut engine_b = Engine::new(b.secret.clone());
    engine_b.configure(named_spec("b-first", &first_on_b));
    engine_a.configure(named_spec("peer-b", &b));
    engine_b.configure(named_spec("peer-a", &a));

    let packet = udp_v4_packet(a.v4, b.v4, b"index-bases-differ");
    let init = engine_a.send_ip_packet(&packet);
    assert_eq!(init.to_network.len(), 1, "首包必须产生握手发起包");
    let response = deliver(&init, &mut engine_b, a.udp);
    assert_eq!(response.to_network.len(), 1, "B 必须回应握手响应");
    let flushed = deliver(&response, &mut engine_a, b.udp);
    assert!(
        !flushed.to_network.is_empty(),
        "A 必须接受 B 的握手响应并补发排队包（而不是按未知索引丢弃）"
    );
    let decrypted = deliver(&flushed, &mut engine_b, a.udp);
    assert_eq!(
        decrypted.to_tunnel,
        vec![packet],
        "序号错开时链路也必须打通"
    );
}

#[test]
fn rotation_converges_when_peer_learns_new_key_before_we_rotate() {
    // 重登录的真实时序：coord 在回调时刻就把新 node_key_pub 推给对端，
    // 本机要等轮询到 Completed 才换私钥；对端先重建、本机后轮换，链路必须收敛。
    let a = test_node("100.96.0.1", "fd12:3456:789a::6460:1", "192.168.1.1:51820");
    let b = test_node("100.96.0.2", "fd12:3456:789a::6460:2", "192.168.1.2:51820");
    let first_on_b = test_node("100.96.0.9", "fd12:3456:789a::6460:9", "192.168.1.9:51820");
    let mut engine_a = Engine::new(a.secret.clone());
    let mut engine_b = Engine::new(b.secret.clone());
    engine_b.configure(named_spec("b-first", &first_on_b));
    engine_a.configure(named_spec("peer-b", &b));
    engine_b.configure(named_spec("peer-a", &a));

    let before = udp_v4_packet(a.v4, b.v4, b"before-rotation");
    let init = engine_a.send_ip_packet(&before);
    let response = deliver(&init, &mut engine_b, a.udp);
    let flushed = deliver(&response, &mut engine_a, b.udp);
    let decrypted = deliver(&flushed, &mut engine_b, a.udp);
    assert_eq!(
        decrypted.to_tunnel,
        vec![before.clone()],
        "轮换前两端必须互通"
    );

    let fresh = NodeStaticSecret::random_from_rng(OsRng);
    let fresh_public = NodePublicKey::from(&fresh).to_bytes();
    engine_b.configure(PeerSpec {
        node_key_pub: fresh_public,
        ..named_spec("peer-a", &a)
    });

    // 本机仍是旧密钥的窗口期：旧密钥流量不得再被对端解出。
    let stale = engine_a.send_ip_packet(&udp_v4_packet(a.v4, b.v4, b"stale-key"));
    let stale_seen = deliver(&stale, &mut engine_b, a.udp);
    assert!(stale_seen.to_tunnel.is_empty(), "密钥更换后旧会话不得续命");

    engine_a.rotate_own_key(fresh);
    engine_a.reconcile(vec![named_spec("peer-b", &b)]);
    let after = udp_v4_packet(a.v4, b.v4, b"after-rotation");
    let init2 = engine_a.send_ip_packet(&after);
    assert_eq!(init2.to_network.len(), 1, "轮换后首个出站包必须重新握手");
    let response2 = deliver(&init2, &mut engine_b, a.udp);
    assert_eq!(response2.to_network.len(), 1, "对端必须回应新密钥握手");
    let flushed2 = deliver(&response2, &mut engine_a, b.udp);
    assert!(!flushed2.to_network.is_empty(), "发起方必须完成新密钥握手");
    let decrypted2 = deliver(&flushed2, &mut engine_b, a.udp);
    assert_eq!(
        decrypted2.to_tunnel,
        vec![after],
        "后轮换的一侧也必须恢复通信"
    );
}

#[test]
fn key_change_rebuild_keeps_learned_endpoints() {
    // 密钥轮换重建会话时，旧密钥期间学到的直连 Endpoint 仍然可达，必须保留。
    let (a, b, mut engine_a, _engine_b) = wired_pair();
    let packet = udp_v4_packet(a.v4, b.v4, b"learn-endpoint");
    let init = engine_a.send_ip_packet(&packet);
    assert_eq!(init.to_network.len(), 1);
    let roamed: SocketAddr = "192.168.1.7:51820".parse().unwrap();
    engine_a.prefer_endpoint(peer_name(&b), roamed);
    assert_eq!(
        engine_a.endpoint_candidates(peer_name(&b)).first(),
        Some(&roamed)
    );

    let fresh_public = NodePublicKey::from(&NodeStaticSecret::random_from_rng(OsRng)).to_bytes();
    engine_a.configure(PeerSpec {
        endpoints: vec![],
        node_key_pub: fresh_public,
        ..spec_for(&b)
    });
    assert_eq!(
        engine_a.endpoint_candidates(peer_name(&b)).first(),
        Some(&roamed),
        "密钥更换重建后学到的 Endpoint 必须保留为首选"
    );
    let out = engine_a.send_ip_packet(&udp_v4_packet(a.v4, b.v4, b"after-key-change"));
    assert!(
        out.to_network.iter().any(|send| send.primary == roamed),
        "重建后的会话必须仍能向学到的 Endpoint 发送"
    );
}

#[test]
fn reset_direct_rx_makes_path_manager_fall_back_and_re_punch() {
    use hz_core::path::{PathEvent, PathManager, PeerEndpoints};
    use std::time::Instant;

    let (a, b, mut engine_a, mut engine_b) = wired_pair();
    let name = peer_name(&a);
    let candidates = PeerEndpoints {
        node_id: name.to_string(),
        stun: vec![a.udp],
        ..Default::default()
    };
    let mut manager = PathManager::new();
    let start = Instant::now();

    // 完整握手交换（发起 → 响应 → 排空），b 直连收到 a 的报文，路径管理升级 Direct。
    let init = engine_a.send_ip_packet(&udp_v4_packet(a.v4, b.v4, b"hi"));
    let response = deliver(&init, &mut engine_b, a.udp);
    let flushed = deliver(&response, &mut engine_a, b.udp);
    let _ = deliver(&flushed, &mut engine_b, a.udp);
    let ages = engine_b.direct_rx_ages();
    let upgrade = manager.tick(start, std::slice::from_ref(&candidates), &ages);
    assert_eq!(
        upgrade,
        vec![PathEvent::SetUseRelay {
            node_id: name.to_string(),
            use_relay: false
        }]
    );

    // 网络变化恢复序列作废直连记账：路径管理立刻退回 Relay；
    // 重启打洞按既有退避节奏（RETRY_START 后的下一拍），不在同一拍里重置
    // 进行中的握手（对称 NAT 下 Relay 会话会因此饿死，见 #8）。
    engine_b.reset_direct_rx();
    let reverted = manager.tick(
        start,
        std::slice::from_ref(&candidates),
        &engine_b.direct_rx_ages(),
    );
    assert_eq!(
        reverted,
        vec![PathEvent::SetUseRelay {
            node_id: name.to_string(),
            use_relay: true
        }]
    );
    // 退避窗口内不重试；窗口过后发出 Offer + 握手（重启打洞轮次）。
    assert!(
        manager
            .tick(
                start + Duration::from_secs(1),
                std::slice::from_ref(&candidates),
                &engine_b.direct_rx_ages()
            )
            .is_empty()
    );
    assert_eq!(
        manager.tick(
            start + Duration::from_secs(5),
            std::slice::from_ref(&candidates),
            &engine_b.direct_rx_ages()
        ),
        vec![
            PathEvent::SendOffer {
                node_id: name.to_string()
            },
            PathEvent::SendHandshake {
                node_id: name.to_string()
            },
        ]
    );
    // 记账清除后打洞握手再次直达对端，direct_rx 重新点亮（恢复后的直连重建路径）。
    let punch = engine_a
        .punch_handshake(peer_name(&b))
        .expect("恢复序列应能重新发出打洞握手");
    let answered = engine_b.handle_udp(a.udp, &punch);
    assert_eq!(answered.to_network.len(), 1, "对端必须应答恢复后的打洞握手");
    assert!(
        engine_b
            .direct_rx_ages()
            .get(name)
            .copied()
            .flatten()
            .is_none(),
        "打洞发起包单独不点亮 direct_rx"
    );
    let _ = engine_a.handle_udp(b.udp, &answered.to_network[0].datagram);
    let follow = engine_a.send_ip_packet(&udp_v4_packet(a.v4, b.v4, b"alive"));
    let _ = deliver(&follow, &mut engine_b, a.udp);
    assert!(
        engine_b
            .direct_rx_ages()
            .get(name)
            .copied()
            .flatten()
            .is_some(),
        "恢复后重新直连必须重新点亮 direct_rx"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn rebind_reapplies_device_idempotently_and_keeps_the_port() {
    use hz_core::wire::{RebindOutcome, SocketEngine};

    // SO_BINDTODEVICE 首次绑定免特权、改绑已绑设备的 socket 才要求
    // CAP_NET_RAW：完全无能力的环境里连重建路径的设备绑定也会失败，
    // 重绑的真实行为由特权容器里的 network-change 场景验证，这里让位。
    let probe = SocketEngine::bind(NodeStaticSecret::random_from_rng(OsRng), 0)
        .await
        .unwrap();
    if probe.rebind("lo").await.is_err() {
        eprintln!("跳过：环境无法设置 SO_BINDTODEVICE，无法验证重绑");
        return;
    }

    let secret = NodeStaticSecret::random_from_rng(OsRng);
    let engine = SocketEngine::bind(secret, 0).await.unwrap();
    let port = engine.local_addr().port();

    // 绑到回环设备（换网卡的等价物）。无 CAP_NET_RAW 时在位改绑必 EPERM、
    // 走重建路径；无论走哪条分支，端口都不能变（对端学到的 Endpoint
    // 依赖它）。
    let first = engine.rebind("lo").await.unwrap();
    assert_eq!(
        engine.local_addr().port(),
        port,
        "重绑无论走在位改绑还是重建都不能换端口：{first:?}"
    );
    // 幂等：重复重绑同一目标是空操作，端口不变。
    assert_eq!(engine.rebind("lo").await.unwrap(), RebindOutcome::Kept);
    assert_eq!(engine.local_addr().port(), port);

    // 目标网卡不存在：改绑失败必须显式报错，不能悄悄换掉 socket 或端口。
    assert!(engine.rebind("hz-no-such-iface").await.is_err());
    assert_eq!(engine.local_addr().port(), port);
    assert_eq!(engine.rebind("lo").await.unwrap(), RebindOutcome::Kept);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn forced_recreate_rebind_deterministically_keeps_the_port() {
    use hz_core::wire::{RebindOutcome, SocketEngine};

    // 无 CAP_NET_RAW 的普通进程改绑已绑设备的 socket 必 EPERM（内核仅放行
    // 首次设备绑定），重绑必然落到重建路径；有特权的环境（如 Docker 默认
    // 能力集含 NET_RAW）在位改绑会成功，用钩子强制同一条重建路径，断言
    // 重建先关旧 socket 再按原端口重绑。常驻收发循环在跑：换出旧 socket
    // 必须先把循环从旧 socket 上唤醒，否则旧引用不释放、原端口腾不出来。
    let engine = std::sync::Arc::new(
        SocketEngine::bind(NodeStaticSecret::random_from_rng(OsRng), 0)
            .await
            .unwrap(),
    );
    let port = engine.local_addr().port();
    let (to_tunnel_tx, _to_tunnel) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    let runner = engine.clone();
    let pump = tokio::spawn(async move {
        let _ = runner.run(to_tunnel_tx).await;
    });

    engine.fail_live_reapply_for_test();
    assert_eq!(
        engine.rebind("lo").await.unwrap(),
        RebindOutcome::Recreated { port },
        "重建路径必须保住原端口"
    );
    assert_eq!(engine.local_addr().port(), port);
    assert_eq!(engine.rebind("lo").await.unwrap(), RebindOutcome::Kept);
    pump.abort();
}
