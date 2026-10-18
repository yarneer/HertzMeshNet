//! FR-5 端到端链路（无需 root）：127.0.0.1 上的真实 UDP/TCP 应答循环 +
//! 真实 NetworkMapCache。查询报文由测试侧手工构造、应答按字面量断言。
//! 客户端用阻塞的 std socket 等应答，必须 multi_thread 运行时，
//! 否则 current_thread 里应答任务永远等不到被轮询。

use std::net::{TcpStream, UdpSocket};
use std::path::Path;
use std::sync::Arc;

use hz_core::map::{MapNode, NetworkMapCache};
use hzd::dns::spawn_responder;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

fn node(name: &str, ipv4: &str, ipv6: &str) -> MapNode {
    MapNode {
        node_id: format!("id-{name}"),
        name: name.to_string(),
        ipv4: ipv4.to_string(),
        ipv6: ipv6.to_string(),
        tags: vec![],
        owner_user: None,
        expires_at_unix: None,
        node_key_pub: vec![],
        endpoints: vec![],
        detailed_endpoints: vec![],
    }
}

fn query(name: &str, qtype: u16) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(&0x4D53u16.to_be_bytes());
    message.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend(&[0; 6]);
    for label in name.split('.') {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    message
}

struct Reply {
    rcode: u8,
    ancount: u16,
    /// 结尾 16 字节：AAAA 应答的 rdata 恰好占满。
    last: Vec<u8>,
    /// 结尾 4 字节：A 应答的 rdata。
    last4: Vec<u8>,
}

fn inspect(message: &[u8]) -> Reply {
    let len = message.len();
    Reply {
        rcode: message[3] & 0x0F,
        ancount: u16::from_be_bytes([message[6], message[7]]),
        last: message[len.saturating_sub(16)..].to_vec(),
        last4: message[len.saturating_sub(4)..].to_vec(),
    }
}

fn udp_round_trip(socket: &UdpSocket, server: std::net::SocketAddr, message: &[u8]) -> Vec<u8> {
    socket.send_to(message, server).unwrap();
    let mut buf = vec![0u8; 1500];
    let (len, _) = socket.recv_from(&mut buf).unwrap();
    buf.truncate(len);
    buf
}

fn cache_with_nodes(state_dir: &Path, nodes: Vec<MapNode>) -> Arc<NetworkMapCache> {
    let cache = Arc::new(NetworkMapCache::empty(state_dir));
    cache.apply_full(nodes);
    cache
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_answers_a_and_aaaa_with_map_literals() {
    let state_dir = tempfile::tempdir().unwrap();
    let cache = cache_with_nodes(
        state_dir.path(),
        vec![node("db-1", "100.96.0.7", "fd12:3456:789a::6460:7")],
    );
    let server = spawn_responder(
        "127.0.0.1:0".parse().unwrap(),
        cache,
        "hznet.internal".to_string(),
    )
    .await
    .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();

    let a_reply = inspect(&udp_round_trip(
        &client,
        server,
        &query("db-1.hznet.internal", TYPE_A),
    ));
    assert_eq!(a_reply.rcode, 0);
    assert_eq!(a_reply.ancount, 1);
    assert_eq!(a_reply.last4, vec![100, 96, 0, 7]);

    let aaaa_reply = inspect(&udp_round_trip(
        &client,
        server,
        &query("db-1.hznet.internal", TYPE_AAAA),
    ));
    assert_eq!(aaaa_reply.rcode, 0);
    assert_eq!(aaaa_reply.ancount, 1);
    assert_eq!(
        aaaa_reply.last,
        vec![
            0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a, 0, 0, 0, 0, 0, 0, 0x64, 0x60, 0, 7
        ]
    );

    let foreign = inspect(&udp_round_trip(
        &client,
        server,
        &query("db-1.example.com", TYPE_A),
    ));
    assert_eq!(foreign.rcode, 5, "后缀外必须 REFUSED");
    assert_eq!(foreign.ancount, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn udp_answers_follow_live_map_updates() {
    let state_dir = tempfile::tempdir().unwrap();
    let cache = cache_with_nodes(state_dir.path(), vec![node("db-1", "100.96.0.7", "fd::7")]);
    let server = spawn_responder(
        "127.0.0.1:0".parse().unwrap(),
        cache.clone(),
        "hznet.internal".to_string(),
    )
    .await
    .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();

    cache.apply_delta(
        vec![node("web-2", "100.96.0.9", "fd::9")],
        vec!["id-db-1".to_string()],
    );
    let reply = inspect(&udp_round_trip(
        &client,
        server,
        &query("web-2.hznet.internal", TYPE_A),
    ));
    assert_eq!(
        (reply.rcode, reply.ancount, reply.last4),
        (0, 1, vec![100, 96, 0, 9])
    );

    let removed = inspect(&udp_round_trip(
        &client,
        server,
        &query("db-1.hznet.internal", TYPE_A),
    ));
    assert_eq!(
        (removed.rcode, removed.ancount),
        (3, 0),
        "移除的 Node 应变 NXDOMAIN"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_suffix_switches_authority() {
    let state_dir = tempfile::tempdir().unwrap();
    let cache = cache_with_nodes(state_dir.path(), vec![node("db-1", "100.96.0.7", "fd::7")]);
    let server = spawn_responder(
        "127.0.0.1:0".parse().unwrap(),
        cache,
        "corp.mesh".to_string(),
    )
    .await
    .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();

    let matched = inspect(&udp_round_trip(
        &client,
        server,
        &query("db-1.corp.mesh", TYPE_A),
    ));
    assert_eq!((matched.rcode, matched.ancount), (0, 1));
    let refused = inspect(&udp_round_trip(
        &client,
        server,
        &query("db-1.hznet.internal", TYPE_A),
    ));
    assert_eq!(refused.rcode, 5, "旧后缀不再归本服务管辖");
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_answers_framed_queries() {
    let state_dir = tempfile::tempdir().unwrap();
    let cache = cache_with_nodes(state_dir.path(), vec![node("db-1", "100.96.0.7", "fd::7")]);
    let server = spawn_responder(
        "127.0.0.1:0".parse().unwrap(),
        cache,
        "hznet.internal".to_string(),
    )
    .await
    .unwrap();

    use std::io::{Read, Write};
    let mut stream = TcpStream::connect(server).unwrap();
    let message = query("db-1.hznet.internal", TYPE_A);
    stream
        .write_all(&(message.len() as u16).to_be_bytes())
        .unwrap();
    stream.write_all(&message).unwrap();

    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).unwrap();
    let mut response = vec![0u8; u16::from_be_bytes(prefix) as usize];
    stream.read_exact(&mut response).unwrap();

    let reply = inspect(&response);
    assert_eq!(reply.rcode, 0);
    assert_eq!(reply.ancount, 1);
    assert_eq!(reply.last4, vec![100, 96, 0, 7]);
}
