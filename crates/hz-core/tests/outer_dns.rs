//! #23：外层连接（Coordination Server / Relay / STUN）的域名解析。系统 DNS
//! 被第三方 TUN 类网络工具接管、返回 198.18.0.0/15 假地址时，改向引导 DNS
//! 重新查询并缓存最近一次有效结果。系统 DNS 经注入替换（系统边界），引导
//! DNS 是测试内真实运行的 UDP DNS 服务。

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hz_core::outer_dns::OuterResolver;

/// 极简引导 DNS：对任何 A 查询回答 `answer`，并统计收到的查询数。
struct BootstrapDns {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
}

fn spawn_bootstrap_dns(answer: Ipv4Addr) -> BootstrapDns {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = queries.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((len, from)) = socket.recv_from(&mut buf) {
            counter.fetch_add(1, Ordering::SeqCst);
            let query = &buf[..len];
            // 问题段结束位置：12 字节头 + 标签序列 + 0 + QTYPE(2) + QCLASS(2)。
            let mut pos = 12;
            while query[pos] != 0 {
                pos += 1 + query[pos] as usize;
            }
            let qtype = u16::from_be_bytes([query[pos + 1], query[pos + 2]]);
            let question_end = pos + 5;
            let mut response = Vec::new();
            response.extend_from_slice(&query[0..2]); // id
            response.extend_from_slice(&[0x81, 0x80]); // QR|RD|RA，NOERROR
            response.extend_from_slice(&[0, 1]); // QDCOUNT
            let ancount: u16 = if qtype == 1 { 1 } else { 0 };
            response.extend_from_slice(&ancount.to_be_bytes());
            response.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT
            response.extend_from_slice(&query[12..question_end]);
            if qtype == 1 {
                response.extend_from_slice(&[0xc0, 0x0c]); // 指向问题段的名字
                response.extend_from_slice(&[0, 1, 0, 1]); // TYPE A, CLASS IN
                response.extend_from_slice(&60u32.to_be_bytes()); // TTL
                response.extend_from_slice(&[0, 4]);
                response.extend_from_slice(&answer.octets());
            }
            let _ = socket.send_to(&response, from);
        }
    });
    BootstrapDns { addr, queries }
}

fn system_returning(ip: &'static str) -> impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> {
    move |_host, port| Ok(vec![SocketAddr::new(ip.parse().unwrap(), port)])
}

#[test]
fn fake_ip_from_system_dns_falls_back_to_bootstrap_dns() {
    let bootstrap = spawn_bootstrap_dns(Ipv4Addr::new(203, 0, 113, 7));
    let resolver =
        OuterResolver::with_system_lookup(vec![bootstrap.addr], system_returning("198.18.2.39"));

    let addrs = resolver.resolve("relay.example.com", 443).unwrap();

    assert_eq!(
        addrs,
        vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            443
        )]
    );
    assert!(bootstrap.queries.load(Ordering::SeqCst) >= 1);
}

#[test]
fn real_answer_from_system_dns_is_used_without_asking_bootstrap() {
    let bootstrap = spawn_bootstrap_dns(Ipv4Addr::new(203, 0, 113, 7));
    let resolver =
        OuterResolver::with_system_lookup(vec![bootstrap.addr], system_returning("124.70.70.12"));

    let addrs = resolver.resolve("coord.example.com", 443).unwrap();

    assert_eq!(addrs, vec!["124.70.70.12:443".parse().unwrap()]);
    assert_eq!(bootstrap.queries.load(Ordering::SeqCst), 0);
}

#[test]
fn last_good_answer_is_reused_when_every_source_fails() {
    // 第一次：系统 DNS 正常；之后系统 DNS 只给假地址，引导 DNS 也不可达。
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let unreachable_bootstrap: SocketAddr = {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap() // 绑定后立即释放：查询将得不到应答
    };
    let resolver =
        OuterResolver::with_system_lookup(vec![unreachable_bootstrap], move |_, port| {
            let ip = if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                "124.70.70.12"
            } else {
                "198.18.0.63"
            };
            Ok(vec![SocketAddr::new(ip.parse().unwrap(), port)])
        });

    let first = resolver.resolve("relay.example.com", 443).unwrap();
    let second = resolver.resolve("relay.example.com", 443).unwrap();

    assert_eq!(second, first);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn fake_ip_range_is_exactly_198_18_slash_15_including_v4_mapped() {
    use hz_core::outer_dns::is_fake_ip;
    for fake in ["198.18.0.1", "198.19.255.255", "::ffff:198.18.0.63"] {
        assert!(is_fake_ip(&fake.parse().unwrap()), "{fake} 应判为假地址");
    }
    for real in [
        "198.17.255.255",
        "198.20.0.0",
        "124.70.70.12",
        "fd7a:3548:1873::1",
    ] {
        assert!(!is_fake_ip(&real.parse().unwrap()), "{real} 不应判为假地址");
    }
}

#[test]
fn macos_scutil_nameservers_skip_fake_and_loopback_servers() {
    use hz_core::outer_dns::parse_scutil_nameservers;
    // 真实 `scutil --dns` 形态：第三方工具的假 DNS 排在首位，物理网卡的
    // DHCP DNS 在按网卡区分的段里，HzNet 自己的分域解析器也会出现。
    let text = "DNS configuration\n\nresolver #1\n  nameserver[0] : 198.18.0.2\n  if_index : 32 (utun4)\n\n\
                resolver #2\n  domain   : hznet.internal\n  nameserver[0] : 10.213.0.53\n\n\
                DNS configuration (for scoped queries)\n\nresolver #1\n  nameserver[0] : 192.168.3.1\n  \
                nameserver[1] : fe80::1%en0\n  if_index : 14 (en0)\n\nresolver #2\n  nameserver[0] : 127.0.0.1\n\n\
                resolver #3\n  nameserver[0] : 192.168.3.1\n";
    assert_eq!(
        parse_scutil_nameservers(text),
        vec!["192.168.3.1".parse::<IpAddr>().unwrap()]
    );
}

#[test]
fn linux_resolv_conf_nameservers_skip_loopback_stub() {
    use hz_core::outer_dns::parse_resolv_conf;
    let text = "# Generated\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver 2001:4860:4860::8888\nsearch lan\n";
    assert_eq!(
        parse_resolv_conf(text),
        vec![
            "192.168.1.1".parse::<IpAddr>().unwrap(),
            "2001:4860:4860::8888".parse().unwrap()
        ]
    );
}

#[test]
fn bootstrap_list_prefers_configured_then_system_then_public() {
    use hz_core::outer_dns::bootstrap_servers;
    let system: Vec<IpAddr> = vec!["192.168.3.1".parse().unwrap()];

    let configured = bootstrap_servers(Some("1.2.3.4, 5.6.7.8:5353"), &system);
    assert_eq!(
        configured,
        vec![
            "1.2.3.4:53".parse().unwrap(),
            "5.6.7.8:5353".parse::<SocketAddr>().unwrap()
        ]
    );

    let defaulted = bootstrap_servers(None, &system);
    assert_eq!(defaulted[0], "192.168.3.1:53".parse().unwrap());
    assert!(
        defaulted.contains(&"223.5.5.5:53".parse().unwrap()),
        "公共 DNS 兜底：{defaulted:?}"
    );
}

#[test]
fn host_port_strings_resolve_including_bracketed_ipv6() {
    use hz_core::outer_dns::resolve_host_port;
    assert_eq!(
        resolve_host_port("203.0.113.1:3478").unwrap(),
        vec!["203.0.113.1:3478".parse::<SocketAddr>().unwrap()]
    );
    assert_eq!(
        resolve_host_port("[2001:db8::1]:443").unwrap(),
        vec!["[2001:db8::1]:443".parse::<SocketAddr>().unwrap()]
    );
    assert!(
        resolve_host_port("relay.example.com").is_err(),
        "缺端口应报错"
    );
}

#[test]
fn bootstrap_fallback_is_recorded_for_status_reporting() {
    let bootstrap = spawn_bootstrap_dns(Ipv4Addr::new(203, 0, 113, 7));
    let resolver =
        OuterResolver::with_system_lookup(vec![bootstrap.addr], system_returning("124.70.70.12"));
    resolver.resolve("coord.example.com", 443).unwrap();
    assert_eq!(resolver.last_fallback(), None, "未回退时不应有记录");

    let resolver =
        OuterResolver::with_system_lookup(vec![bootstrap.addr], system_returning("198.18.2.39"));
    resolver.resolve("relay.example.com", 443).unwrap();
    let fallback = resolver.last_fallback().expect("回退应被记录");
    assert_eq!(fallback.host, "relay.example.com");
    assert!(
        fallback.at > 1_700_000_000,
        "记录时间应为 Unix 秒：{}",
        fallback.at
    );
}

// 审查 (b)1：#23 只针对"返回假地址"。系统 DNS 单纯失败（断网、NXDOMAIN）时
// 不改问引导 DNS、也不记为回退，只沿用缓存。
#[test]
fn system_dns_failure_is_not_treated_as_hijack() {
    let bootstrap = spawn_bootstrap_dns(Ipv4Addr::new(203, 0, 113, 7));
    let resolver = OuterResolver::with_system_lookup(vec![bootstrap.addr], |_, _| {
        Err(io::Error::other("temporary failure in name resolution"))
    });

    assert!(resolver.resolve("relay.example.com", 443).is_err());
    assert_eq!(
        bootstrap.queries.load(Ordering::SeqCst),
        0,
        "不应询问引导 DNS"
    );
    assert!(resolver.last_fallback().is_none(), "不应记为引导 DNS 回退");
}
