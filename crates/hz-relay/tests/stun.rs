//! #76：Relay 缺省开两个 STUN 端口，两个端口都要能回 Binding Response。
//! 未放行第二个端口的旧部署语义（目标超时 → nat=unknown）在 hzd 侧处理，
//! 这里只验证服务器侧行为。

use std::net::SocketAddr;
use std::time::Duration;

use hz_core::stun::{binding_request, parse_mapped_address};

async fn query(server: SocketAddr) -> Option<SocketAddr> {
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (_, request) = binding_request();
    client.send_to(&request, server).await.ok()?;
    let mut buf = [0u8; 256];
    let (len, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_mapped_address(&buf[..len])
}

#[tokio::test]
async fn both_default_style_stun_ports_answer_binding_requests() {
    // 127.0.0.1:0 拿两个临时端口，模拟缺省的 3478 / 3479 双监听。
    let listens = vec!["127.0.0.1:0".to_string(), "127.0.0.1:0".to_string()];
    let bound = hz_relay::start_stun(&listens).await.unwrap();
    assert_eq!(bound.len(), 2, "两个监听都应绑定：{bound:?}");

    for server in &bound {
        let mapped = query(*server)
            .await
            .unwrap_or_else(|| panic!("{server} 未应答 STUN Binding Request"));
        assert!(mapped.ip().is_loopback());
    }

    // 同一客户端先后问两个端口：映射端口相同（本机无 NAT），对应 nat=easy
    // 的判定输入；这里是服务器侧行为的对照。
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ports: Vec<u16> = {
        let mut ports = Vec::new();
        for server in &bound {
            let (_, request) = binding_request();
            client.send_to(&request, *server).await.unwrap();
            let mut buf = [0u8; 256];
            let (len, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            ports.push(parse_mapped_address(&buf[..len]).unwrap().port());
        }
        ports
    };
    assert_eq!(ports[0], ports[1]);
}

#[tokio::test]
async fn invalid_stun_listen_is_rejected() {
    let bad = vec!["not-an-addr".to_string()];
    assert!(hz_relay::start_stun(&bad).await.is_err());
}
