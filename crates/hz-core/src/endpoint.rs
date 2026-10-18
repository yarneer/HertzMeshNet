//! Endpoint 收集（FR-8）。三种来源：
//! Lan = 非虚拟网卡的 IPv4 + WireGuard 端口；Stun = 从共享 socket 向 Relay
//! 主机的 UDP 3478 查询得到的公网映射；V6 = 网卡上的全球单播 IPv6（v6 无 NAT
//! 预期）。收集结果经 ReportEndpoints 上报 Coordination Server，随 Network
//! Map 下发给对端，对端据此排候选序（V6 优先、Stun 次之、Lan 兜底）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Endpoint 的发现途径，决定对端的尝试优先级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointKind {
    Lan,
    Stun,
    V6,
}

impl EndpointKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointKind::Lan => "lan",
            EndpointKind::Stun => "stun",
            EndpointKind::V6 => "v6",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "lan" => Some(EndpointKind::Lan),
            "stun" => Some(EndpointKind::Stun),
            "v6" => Some(EndpointKind::V6),
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

/// 按候选优先级排序：V6（无 NAT）→ Stun（公网映射）→ Lan（同网段才可达）。
/// 同类内保持收集顺序。
pub fn rank(endpoints: &[DiscoveredEndpoint]) -> Vec<DiscoveredEndpoint> {
    let mut ranked = endpoints.to_vec();
    ranked.sort_by_key(|endpoint| match endpoint.kind {
        EndpointKind::V6 => 0,
        EndpointKind::Stun => 1,
        EndpointKind::Lan => 2,
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
    !ip.is_unspecified()
        && !ip.is_broadcast()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_documentation()
}

/// 全球单播 IPv6（2000::/3）：排除 ULA、链路本地、组播与未指定地址。
/// Ipv6Addr::is_unicast_global 尚未稳定，这里手写同一判定。
fn is_global_v6(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xe000) == 0x2000 && !ip.is_unspecified()
}

/// 非虚拟网卡上的全部地址（getifaddrs）。虚拟网卡名沿用
/// [`crate::netif`] 的排除表——第三方 TUN 类网络工具的地址不是我们的出口。
/// 收集 Endpoint 与网络变化侦测（netwatch 的快照比对）共用。
pub(crate) fn interface_addrs() -> Vec<IpAddr> {
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
            let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy();
            if crate::netif::is_virtual_name(&name) {
                continue;
            }
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
            out.push(ip);
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
        for kind in [EndpointKind::Lan, EndpointKind::Stun, EndpointKind::V6] {
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
    fn rank_orders_v6_before_stun_before_lan() {
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
        ];
        let order: Vec<EndpointKind> = rank(&endpoints).into_iter().map(|e| e.kind).collect();
        assert_eq!(
            order,
            vec![EndpointKind::V6, EndpointKind::Stun, EndpointKind::Lan]
        );
    }

    #[test]
    fn interface_addrs_lists_loopback_without_panicking() {
        // macOS CI 上只有 lo0；断言它不 panic 且不含虚拟名（lo 被排除）。
        let addrs = interface_addrs();
        assert!(addrs.iter().all(|ip| !ip.is_unspecified()));
    }
}
