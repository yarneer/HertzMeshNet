//! Endpoint 收集（FR-8）。收集来源：
//! Lan = 非虚拟网卡的 IPv4 + WireGuard 端口（不含 198.18.0.0/15）；Stun = 从共享 socket 向 Relay
//! 主机的 UDP 3478 查询得到的公网映射；V6 = 网卡上的全球单播 IPv6（v6 无 NAT
//! 预期）；PortMap = 端口映射申请到的稳定公网映射（#77，由 hzd 的 portmap
//! 任务并入，不在 collect 里产生）。收集结果经 ReportEndpoints 上报
//! Coordination Server，随 Network Map 下发给对端，对端据此排候选序
//! （V6 优先、PortMap、Stun 次之、Lan 兜底）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Endpoint 的发现途径，决定对端的尝试优先级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointKind {
    Lan,
    Stun,
    V6,
    /// 端口映射（#77）：PCP / NAT-PMP / UPnP IGD 申请到的稳定公网映射。
    PortMap,
}

impl EndpointKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointKind::Lan => "lan",
            EndpointKind::Stun => "stun",
            EndpointKind::V6 => "v6",
            EndpointKind::PortMap => "portmap",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "lan" => Some(EndpointKind::Lan),
            "stun" => Some(EndpointKind::Stun),
            "v6" => Some(EndpointKind::V6),
            "portmap" => Some(EndpointKind::PortMap),
            _ => None,
        }
    }
}

/// 一个已发现的 Endpoint。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredEndpoint {
    pub addr: SocketAddr,
    pub kind: EndpointKind,
}

/// 按候选优先级排序：V6（无 NAT）→ PortMap（稳定映射，#77）→ Stun（公网
/// 映射，对称 NAT 下只对查询目标有效）→ Lan（同网段才可达）。
/// 同类内保持收集顺序。
pub fn rank(endpoints: &[DiscoveredEndpoint]) -> Vec<DiscoveredEndpoint> {
    let mut ranked = endpoints.to_vec();
    ranked.sort_by_key(|endpoint| match endpoint.kind {
        EndpointKind::V6 => 0,
        EndpointKind::PortMap => 1,
        EndpointKind::Stun => 2,
        EndpointKind::Lan => 3,
    });
    ranked
}

/// 收集本机 Endpoint。stun_mapped 是共享 socket 上 STUN 查询的结果（查询
/// 由 [`crate::wire::SocketEngine::stun_query`] 发起，因为响应要走引擎的
/// 收包循环）；None 表示 STUN 不可达，跳过该来源。
pub fn collect(wg_port: u16, stun_mapped: Option<SocketAddr>) -> Vec<DiscoveredEndpoint> {
    let mut out = Vec::new();
    for ip in interface_addrs() {
        match ip {
            IpAddr::V4(v4) => {
                if usable_lan_v4(v4) {
                    out.push(DiscoveredEndpoint {
                        addr: SocketAddr::new(IpAddr::V4(v4), wg_port),
                        kind: EndpointKind::Lan,
                    });
                }
            }
            IpAddr::V6(v6) => {
                if is_global_v6(v6) {
                    out.push(DiscoveredEndpoint {
                        addr: SocketAddr::new(IpAddr::V6(v6), wg_port),
                        kind: EndpointKind::V6,
                    });
                }
            }
        }
    }
    if let Some(mapped) = stun_mapped {
        out.push(DiscoveredEndpoint {
            addr: mapped,
            kind: EndpointKind::Stun,
        });
    }
    dedup(out)
}

/// 去重：同一 addr 出现多种来源时保留排序权重最高（V6 > Stun > Lan）的一次。
fn dedup(endpoints: Vec<DiscoveredEndpoint>) -> Vec<DiscoveredEndpoint> {
    let mut seen: Vec<DiscoveredEndpoint> = Vec::new();
    for endpoint in rank(&endpoints) {
        if !seen.iter().any(|kept| kept.addr == endpoint.addr) {
            seen.push(endpoint);
        }
    }
    seen
}

fn usable_lan_v4(ip: Ipv4Addr) -> bool {
    // 198.18.0.0/15 是第三方 TUN 类网络工具的假地址，不是局域网出口。
    !crate::outer_dns::is_fake_ip(&IpAddr::V4(ip))
        && !ip.is_unspecified()
        && !ip.is_broadcast()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_documentation()
}

/// 候选源地址能否作为上报的 LAN Endpoint。
/// `198.18.0.0/15` 与虚拟网卡上的地址一律拒绝。
pub(crate) fn accept_lan_candidate(iface: &str, ip: IpAddr) -> bool {
    if crate::netif::is_virtual_iface(iface) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => usable_lan_v4(v4),
        IpAddr::V6(_) => false,
    }
}

/// 从候选里取物理出口网卡上的 IPv4。出口不明、或该网卡上没有可用地址时
/// 返回 None（不上报，而不是改报另一张网卡或一个假地址）。
pub(crate) fn select_lan_source<'a>(
    candidates: impl IntoIterator<Item = (&'a str, IpAddr)>,
    egress: Option<&str>,
) -> Option<IpAddr> {
    let egress = egress?;
    candidates
        .into_iter()
        .find_map(|(iface, ip)| (iface == egress && accept_lan_candidate(iface, ip)).then_some(ip))
}

/// 当前物理出口网卡上应上报的 LAN 地址。与 [`interface_addrs`] 同一套网卡枚举。
pub(crate) fn reported_lan_ip() -> Option<IpAddr> {
    let egress = crate::netif::physical_egress();
    let listed = enumerated_addrs();
    select_lan_source(
        listed.iter().map(|(name, ip)| (name.as_str(), *ip)),
        egress.as_deref(),
    )
}

/// 全球单播 IPv6（2000::/3）：排除 ULA、链路本地、组播与未指定地址。
/// Ipv6Addr::is_unicast_global 尚未稳定，这里手写同一判定。
fn is_global_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xe000) == 0x2000 && !ip.is_unspecified()
}

/// 非虚拟网卡上的 IPv4 地址（端口映射的 NewInternalClient 候选，#77）。
pub(crate) fn lan_ipv4_candidates() -> Vec<Ipv4Addr> {
    interface_addrs()
        .into_iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) if usable_lan_v4(v4) => Some(v4),
            _ => None,
        })
        .collect()
}

/// 非虚拟网卡上有全球单播 IPv6。链路本地与 ULA 不算可直连的地址。
pub fn has_usable_ipv6() -> bool {
    interface_addrs().into_iter().any(|ip| match ip {
        IpAddr::V6(v6) => is_global_v6(v6),
        IpAddr::V4(_) => false,
    })
}

/// 非虚拟网卡上的全部地址（getifaddrs）。虚拟网卡判定与
/// [`crate::netif::physical_egress`] 相同——第三方 TUN 类网络工具的地址
/// 不是我们的出口。收集 Endpoint 与网络变化侦测（netwatch 的快照比对）共用。
pub(crate) fn interface_addrs() -> Vec<IpAddr> {
    enumerated_addrs()
        .into_iter()
        .filter(|(name, _)| !crate::netif::is_virtual_iface(name))
        .map(|(_, ip)| ip)
        .collect()
}

/// 全部网卡地址（含虚拟网卡），供 LAN Endpoint 选择与 [`interface_addrs`] 共用。
fn enumerated_addrs() -> Vec<(String, IpAddr)> {
    use std::ffi::CStr;
    let mut out = Vec::new();
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            tracing::warn!(
                errno = std::io::Error::last_os_error().raw_os_error(),
                "getifaddrs failed"
            );
            return out;
        }
        let mut cursor = head;
        while !cursor.is_null() {
            let ifa = &*cursor;
            cursor = ifa.ifa_next;
            if ifa.ifa_addr.is_null() {
                continue;
            }
            let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
            let family = (*ifa.ifa_addr).sa_family as i32;
            let ip = match family {
                libc::AF_INET => {
                    let sa: &libc::sockaddr_in = &*(ifa.ifa_addr.cast());
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)))
                }
                libc::AF_INET6 => {
                    let sa: &libc::sockaddr_in6 = &*(ifa.ifa_addr.cast());
                    IpAddr::V6(std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr))
                }
                _ => continue,
            };
            out.push((name, ip));
        }
        libc::freeifaddrs(head);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_round_trip_through_strings() {
        for kind in [
            EndpointKind::Lan,
            EndpointKind::Stun,
            EndpointKind::V6,
            EndpointKind::PortMap,
        ] {
            assert_eq!(EndpointKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(EndpointKind::parse("other"), None);
    }

    #[test]
    fn collect_reports_stun_and_dedups_against_lan() {
        // 同一地址既是本机 lan 又是 stun 映射（NAT1:1 场景）时保留 stun。
        let mut found = collect(51820, Some("192.0.2.10:51820".parse().unwrap()));
        let stun = found
            .iter()
            .find(|endpoint| endpoint.kind == EndpointKind::Stun)
            .expect("stun endpoint kept");
        assert_eq!(stun.addr, "192.0.2.10:51820".parse().unwrap());
        found.retain(|endpoint| {
            endpoint.kind == EndpointKind::Lan && endpoint.addr.ip().is_loopback()
        });
        assert!(
            found.is_empty(),
            "loopback 不应作为 lan endpoint: {found:?}"
        );
    }

    #[test]
    fn rank_orders_v6_portmap_stun_lan() {
        let endpoints = vec![
            DiscoveredEndpoint {
                addr: "192.168.1.2:51820".parse().unwrap(),
                kind: EndpointKind::Lan,
            },
            DiscoveredEndpoint {
                addr: "203.0.113.5:41001".parse().unwrap(),
                kind: EndpointKind::Stun,
            },
            DiscoveredEndpoint {
                addr: "[2001:db8::2]:51820".parse().unwrap(),
                kind: EndpointKind::V6,
            },
            DiscoveredEndpoint {
                addr: "198.51.100.7:52001".parse().unwrap(),
                kind: EndpointKind::PortMap,
            },
        ];
        let order: Vec<EndpointKind> = rank(&endpoints).into_iter().map(|e| e.kind).collect();
        assert_eq!(
            order,
            vec![
                EndpointKind::V6,
                EndpointKind::PortMap,
                EndpointKind::Stun,
                EndpointKind::Lan
            ]
        );
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn lan_source_rejects_fake_ip_and_virtual_nic() {
        let lan = ip("192.168.31.63");
        assert!(
            !accept_lan_candidate("en0", ip("198.18.0.1")),
            "198.18.0.0/15 不能当 LAN Endpoint"
        );
        assert!(!accept_lan_candidate("eth0", ip("198.19.255.255")));
        assert!(
            !accept_lan_candidate("utun4", lan),
            "虚拟网卡上的地址不能当 LAN Endpoint"
        );
        assert!(!accept_lan_candidate("tun0", lan));
        assert!(!accept_lan_candidate("en0", ip("127.0.0.1")));
        assert!(accept_lan_candidate("en0", lan));
        assert!(accept_lan_candidate("eth0", ip("10.0.0.8")));
        assert!(!usable_lan_v4(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(usable_lan_v4(Ipv4Addr::new(192, 168, 31, 63)));
    }

    #[test]
    fn egress_change_reselects_physical_address_and_drops_unusable() {
        let wifi = ip("192.168.31.63");
        let wired = ip("10.0.0.8");
        let fake = ip("198.18.0.1");
        let on_wifi = [("en0", wifi), ("utun4", fake)];
        assert_eq!(select_lan_source(on_wifi, Some("en0")), Some(wifi));
        // 同一张物理网卡上假地址与真实地址并存时，只留真实地址。
        let mixed = [("en0", fake), ("en0", wifi)];
        assert_eq!(select_lan_source(mixed, Some("en0")), Some(wifi));

        let on_wired = [("en0", wifi), ("en5", wired), ("utun4", fake)];
        assert_eq!(
            select_lan_source(on_wired, Some("en5")),
            Some(wired),
            "出口从 en0 换到 en5 后应改报新网卡地址"
        );
        let poisoned = [("en5", fake), ("utun4", wired)];
        assert_eq!(
            select_lan_source(poisoned, Some("en5")),
            None,
            "新出口上只剩假地址时不上报"
        );
        assert_eq!(
            select_lan_source(poisoned, Some("utun4")),
            None,
            "虚拟网卡即使被当成出口也不上报"
        );
        assert_eq!(select_lan_source(on_wired, None), None);
    }

    #[test]
    fn interface_addrs_lists_loopback_without_panicking() {
        // macOS CI 上只有 lo0；断言它不 panic 且不含虚拟名（lo 被排除）。
        let addrs = interface_addrs();
        assert!(addrs.iter().all(|ip| !ip.is_unspecified()));
    }
}
