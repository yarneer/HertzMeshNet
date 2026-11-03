//! #98 DNS 转发模式（规格 §5.2）：后缀外查询经 `Platform::protect` 的
//! socket 转发给 `Platform::system_dns()` 的上游。假上游 + 假 Platform 覆盖：
//! 后缀内照旧本地应答、UDP 转发、TC 截断改 TCP、全失败 SERVFAIL、
//! 服务器列表更新、转发 socket 经 protect。

use std::net::{IpAddr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use hz_core::map::{MapNode, NetworkMapCache};
use hz_core::tun::TunIo;
use hz_engine::dns::{Forwarding, spawn_responder};
use hz_engine::{Platform, TunSpec};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;

// 各测试把假上游端口写进这里（应答器构造时读取）。
thread_local! {
    static UPSTREAM_PORT: std::cell::Cell<u16> = const { std::cell::Cell::new(53) };
}

/// 可变 system_dns 列表的假平台；protect 只记录 fd。
struct FakePlatform {
    dns: StdMutex<Vec<IpAddr>>,
    protected: StdMutex<Vec<RawFd>>,
}

impl Platform for FakePlatform {
    fn establish(&self, _spec: TunSpec) -> anyhow::Result<Arc<dyn TunIo>> {
        anyhow::bail!("无 TUN（本测试只测转发）")
    }

    fn protect(&self, fd: RawFd) -> bool {
        self.protected.lock().unwrap().push(fd);
        true
    }

    fn net_events(&self) -> mpsc::Receiver<hz_core::netwatch::NetEvent> {
        mpsc::channel(1).1
    }

    fn system_dns(&self) -> Vec<IpAddr> {
        self.dns.lock().unwrap().clone()
    }
}

/// 假上游：UDP 收查询后回一个 A 应答；tcp_framed 模式下先起 TCP 监听。
/// `trunc_udp` 控制 UDP 应答是否带 TC 位（迫使客户端转 TCP）。
struct FakeUpstream {
    udp: Arc<tokio::net::UdpSocket>,
}

impl FakeUpstream {
    /// port=0 随机；指定端口时 UDP/TCP 都绑它（列表刷新测试复用同一端口）。
    async fn start_at(port: u16, trunc_udp: bool) -> Self {
        let udp = Arc::new(
            tokio::net::UdpSocket::bind(("127.0.0.1", port))
                .await
                .expect("UDP 上游端口可绑"),
        );
        // TCP 与 UDP 同端口（转发实现对两种协议用同一 upstream_port）。
        let udp_port = udp.local_addr().unwrap().port();
        let tcp = tokio::net::TcpListener::bind(("127.0.0.1", udp_port))
            .await
            .expect("TCP 与 UDP 应能绑同一端口（协议端口空间独立）");
        // UDP 应答循环：原样回 query id + flags（QR，可选 TC）+ 一个 A 记录，
        // 应答体含标记字节，测试据此区分 UDP / TCP 来源。
        let pump = {
            let udp = udp.clone();
            async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let Ok((len, peer)) = udp.recv_from(&mut buf).await else {
                        continue;
                    };
                    let response = upstream_answer(&buf[..len], trunc_udp, b'U');
                    let _ = udp.send_to(&response, peer).await;
                }
            }
        };
        tokio::spawn(pump);
        // TCP 应答循环：2 字节长度前缀成帧。
        let tcp_addr = tcp.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = tcp.accept().await else {
                    continue;
                };
                let mut prefix = [0u8; 2];
                if stream.read_exact(&mut prefix).await.is_err() {
                    continue;
                }
                let len = u16::from_be_bytes(prefix) as usize;
                let mut query = vec![0u8; len];
                if stream.read_exact(&mut query).await.is_err() {
                    continue;
                }
                let response = upstream_answer(&query, false, b'T');
                let mut framed = (response.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&response);
                let _ = stream.write_all(&framed).await;
            }
        });
        let _ = tcp_addr;
        UPSTREAM_PORT.with(|p| p.set(udp.local_addr().unwrap().port()));
        Self { udp }
    }

    async fn start(trunc_udp: bool) -> Self {
        Self::start_at(0, trunc_udp).await
    }

    fn ip(&self) -> IpAddr {
        self.udp.local_addr().unwrap().ip()
    }
}

/// 构造上游应答：沿用 query id，QR 置位，可选 TC，answer 区带一个 A 记录，
/// rdata 首字节是来源标记（'U' = UDP / 'T' TCP）。
fn upstream_answer(query: &[u8], trunc: bool, marker: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(query.len() + 16);
    out.extend_from_slice(&query[..2]);
    let mut flags = 0x8000u16; // QR
    flags |= u16::from(query.get(2).map(|b| b & 0x01).unwrap_or(0)) << 8; // 回显 RD
    if trunc {
        flags |= 0x0200; // TC
    }
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount 回显 1
    out.extend_from_slice(&1u16.to_be_bytes()); // ancount
    out.extend_from_slice(&[0; 4]);
    // 问题区原样拷贝（从 offset 12 起）。
    out.extend_from_slice(&query[12..]);
    // answer：name 指针回 question（0xC00C）+ A + IN + TTL + 4 字节 rdata。
    out.extend_from_slice(&[0xC0, 0x0C]);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&60u32.to_be_bytes());
    out.extend_from_slice(&4u16.to_be_bytes());
    out.extend_from_slice(&[marker, 1, 2, 3]);
    out
}

fn wire_query(id: u16, labels: &[&[u8]], qtype: u16) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&[0; 6]);
    for label in labels {
        query.push(label.len() as u8);
        query.extend_from_slice(label);
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query
}

fn cache_with_db1() -> Arc<NetworkMapCache> {
    let cache = Arc::new(NetworkMapCache::empty(std::path::Path::new(
        "/tmp/hz-dns-fwd-test",
    )));
    let node = MapNode {
        node_id: "id-db-1".into(),
        name: "db-1".into(),
        ipv4: "100.96.0.7".into(),
        ipv6: "fd12:3456:789a::6460:7".into(),
        tags: vec![],
        owner_user: None,
        expires_at_unix: None,
        node_key_pub: vec![],
        endpoints: vec![],
        detailed_endpoints: vec![],
    };
    cache.apply_full(vec![node]);
    cache
}

fn rcode(response: &[u8]) -> u8 {
    response[3] & 0x0F
}

/// 起应答器（回环随机端口）+ 返回客户端用的 UDP socket。
async fn responder_with(platform: &Arc<FakePlatform>) -> SocketAddr {
    spawn_responder(
        "127.0.0.1:0".parse().unwrap(),
        cache_with_db1(),
        "hznet.internal".to_string(),
        Some(Forwarding {
            platform: platform.clone(),
            timeout: Duration::from_millis(500),
            upstream_port: UPSTREAM_PORT.get(),
        }),
    )
    .await
    .unwrap()
}

async fn ask(responder: SocketAddr, query: &[u8]) -> Vec<u8> {
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(query, responder).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let (len, _) = client.recv_from(&mut buf).await.unwrap();
    buf[..len].to_vec()
}

#[tokio::test]
async fn suffix_local_answers_unchanged_with_forwarding_on() {
    let platform = Arc::new(FakePlatform {
        dns: StdMutex::new(vec![]),
        protected: StdMutex::new(vec![]),
    });
    let responder = responder_with(&platform).await;
    let response = ask(
        responder,
        &wire_query(7, &[b"db-1", b"hznet", b"internal"], 1),
    )
    .await;
    assert_eq!(rcode(&response), 0);
    assert_eq!(
        &response[response.len() - 4..],
        &[100, 96, 0, 7],
        "仍本地应答"
    );
}

#[tokio::test]
async fn out_of_suffix_forwards_over_udp() {
    let upstream = FakeUpstream::start(false).await;
    let platform = Arc::new(FakePlatform {
        dns: StdMutex::new(vec![upstream.ip()]),
        protected: StdMutex::new(vec![]),
    });
    let responder = responder_with(&platform).await;
    let response = ask(responder, &wire_query(9, &[b"example", b"com"], 1)).await;
    assert_eq!(rcode(&response), 0, "上游应答原样透传");
    assert_eq!(
        &response[response.len() - 4..],
        &[b'U', 1, 2, 3],
        "来自 UDP 上游"
    );
    assert!(
        !platform.protected.lock().unwrap().is_empty(),
        "转发 socket 必须经 Platform::protect"
    );
}

#[tokio::test]
async fn truncated_udp_answer_falls_back_to_tcp() {
    let upstream = FakeUpstream::start(true).await;
    let platform = Arc::new(FakePlatform {
        dns: StdMutex::new(vec![upstream.ip()]),
        protected: StdMutex::new(vec![]),
    });
    let responder = responder_with(&platform).await;
    let response = ask(responder, &wire_query(11, &[b"example", b"org"], 1)).await;
    assert_eq!(rcode(&response), 0);
    assert_eq!(
        &response[response.len() - 4..],
        &[b'T', 1, 2, 3],
        "TC 截断后改走 TCP 上游"
    );
}

#[tokio::test]
async fn all_upstreams_failing_yields_servfail() {
    // 死端口：绑定后立即关闭，转发必然超时。
    let dead = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    UPSTREAM_PORT.with(|p| p.set(dead_addr.port()));
    let platform = Arc::new(FakePlatform {
        dns: StdMutex::new(vec![dead_addr.ip()]),
        protected: StdMutex::new(vec![]),
    });
    let responder = responder_with(&platform).await;
    let response = ask(responder, &wire_query(13, &[b"example", b"net"], 1)).await;
    assert_eq!(rcode(&response), 2, "全部上游失败回 SERVFAIL");
    let _ = upstream_answer; // 共享构造器
}

#[tokio::test]
async fn upstream_list_refresh_uses_new_servers() {
    // 固定一个端口：第一轮无人监听（列表指向 127.0.0.1 但服务未起）；
    // 上游绑同一端口后列表刷新为同一服务器，第二轮应成功。
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    UPSTREAM_PORT.with(|p| p.set(port));
    let platform = Arc::new(FakePlatform {
        dns: StdMutex::new(vec![[127u8, 0, 0, 1].into()]),
        protected: StdMutex::new(vec![]),
    });
    let responder = responder_with(&platform).await;
    let first = ask(responder, &wire_query(15, &[b"example", b"io"], 1)).await;
    assert_eq!(rcode(&first), 2, "旧列表（死端口）应 SERVFAIL");

    // system_dns "变化"（同一服务器重新可达）+ 真上游占用该端口。
    let upstream = FakeUpstream::start_at(port, false).await;
    *platform.dns.lock().unwrap() = vec![upstream.ip()];
    let second = ask(responder, &wire_query(16, &[b"example", b"io"], 1)).await;
    assert_eq!(rcode(&second), 0, "system_dns 变化后用新列表");
    assert_eq!(&second[second.len() - 4..], &[b'U', 1, 2, 3]);
}

#[tokio::test]
async fn empty_upstream_list_is_servfail() {
    let platform = Arc::new(FakePlatform {
        dns: StdMutex::new(vec![]),
        protected: StdMutex::new(vec![]),
    });
    let responder = responder_with(&platform).await;
    let response = ask(responder, &wire_query(17, &[b"example", b"dev"], 1)).await;
    assert_eq!(rcode(&response), 2, "空上游列表视同全部失败");
}
