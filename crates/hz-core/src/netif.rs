//! 隧道外层流量的物理出口网卡（FR-7 与第三方 TUN 类网络工具共存）。
//! hzd 的全部外层流量（WireGuard/打洞 UDP、到 Coordination Server 的连接）
//! 在创建 socket 时就绑到物理出口网卡，不进入接管默认路由的虚拟网卡。
//! Linux 用 SO_BINDTODEVICE；macOS 用 IP_BOUND_IF / IPV6_BOUND_IF
//! （socket2 把这两个选项闸在非默认 feature 后面，这里直接经 libc setsockopt）。
//! 出口变化后的重绑不在本模块（见 #9/#16）。

#[cfg(any(target_os = "linux", test))]
use std::net::Ipv4Addr;
use std::os::fd::AsFd;
#[cfg(target_os = "macos")]
use std::os::unix::io::AsRawFd;

/// 虚拟网卡的名称前缀排除表。第三方 TUN 类网络工具可能用表外名字创建
/// tun 设备，Linux 上另用 `/sys/class/net/<if>/tun_flags` 的存在性兜底。
const VIRTUAL_NAME_PREFIXES: &[&str] = &[
    "lo", "tun", "tap", "hz", "utun", "docker", "veth", "br-", "bridge", "zt", "awdl", "llw",
];

/// `/proc/net/route` 的一条 IPv4 路由。
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteEntry {
    pub iface: String,
    pub dest: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub metric: u32,
}

/// 名称前缀意义上的虚拟网卡判定。
pub fn is_virtual_name(name: &str) -> bool {
    VIRTUAL_NAME_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Linux：tun/tap 字符设备创建的接口会在 sysfs 暴露 tun_flags，
/// 无论第三方 TUN 类网络工具给它起什么名字都能识别。
#[cfg(target_os = "linux")]
fn is_tun_device(name: &str) -> bool {
    std::path::Path::new("/sys/class/net")
        .join(name)
        .join("tun_flags")
        .exists()
}

/// 从路由表条目里选出物理出口网卡：
/// 默认路由持有者（metric 最小）优先；默认路由被虚拟网卡夺走时，
/// 退到仍承载网段路由的物理网卡。找不到返回 None。
#[cfg(any(target_os = "linux", test))]
pub(crate) fn pick_egress(
    routes: &[RouteEntry],
    is_virtual: &dyn Fn(&str) -> bool,
) -> Option<String> {
    let mut defaults: Vec<&RouteEntry> = routes
        .iter()
        .filter(|r| r.dest.is_unspecified() && r.mask.is_unspecified())
        .collect();
    defaults.sort_by_key(|r| r.metric);
    if let Some(picked) = defaults.iter().find(|r| !is_virtual(&r.iface)) {
        return Some(picked.iface.clone());
    }
    let mut subnets: Vec<&RouteEntry> = routes
        .iter()
        .filter(|r| !r.mask.is_unspecified() && !r.dest.is_unspecified())
        .collect();
    subnets.sort_by_key(|r| r.metric);
    subnets
        .iter()
        .find(|r| !is_virtual(&r.iface))
        .map(|r| r.iface.clone())
}

/// 持有地址 `ip` 的本机网卡名（getifaddrs）。用于 `hz status` 指出 HzNet
/// 流量实际从哪张网卡发出（#25）。
#[cfg(unix)]
pub fn interface_with_addr(ip: std::net::IpAddr) -> Option<String> {
    use std::ffi::CStr;
    use std::net::{Ipv4Addr, Ipv6Addr};
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs 成功时链表由 freeifaddrs 释放；遍历只读其中字段。
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return None;
        }
        let mut found = None;
        let mut cursor = head;
        while !cursor.is_null() {
            let entry = &*cursor;
            cursor = entry.ifa_next;
            if entry.ifa_addr.is_null() {
                continue;
            }
            let family = i32::from((*entry.ifa_addr).sa_family);
            let addr = if family == libc::AF_INET {
                let sin = &*(entry.ifa_addr as *const libc::sockaddr_in);
                std::net::IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
            } else if family == libc::AF_INET6 {
                let sin6 = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                std::net::IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr))
            } else {
                continue;
            };
            if addr == ip {
                found = Some(
                    CStr::from_ptr(entry.ifa_name)
                        .to_string_lossy()
                        .into_owned(),
                );
                break;
            }
        }
        libc::freeifaddrs(head);
        found
    }
}

/// 当前物理出口网卡。探测不到（无路由表、全是虚拟网卡）返回 None。
pub fn physical_egress() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        let routes = parse_route_table(&table);
        let picked = pick_egress(&routes, &|name| {
            is_virtual_name(name) || is_tun_device(name)
        });
        match picked {
            Some(iface) => {
                tracing::debug!(%iface, "physical egress interface detected");
                Some(iface)
            }
            None => {
                tracing::warn!("no physical egress interface found");
                None
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let picked = egress_from_route_get()
            .filter(|name| !is_virtual_name(name))
            .or_else(egress_from_netstat);
        match picked {
            Some(iface) => {
                tracing::debug!(%iface, "physical egress interface detected");
                Some(iface)
            }
            None => {
                tracing::warn!("no physical egress interface found");
                None
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// 把 socket 绑到物理出口网卡（Linux SO_BINDTODEVICE、macOS IP_BOUND_IF，
/// 都须在 connect(2)/发包之前生效）。返回绑定的网卡名；探测或设置失败时
/// 返回 None，外层流量退回系统路由并记录告警（此时与第三方 TUN 类网络
/// 工具的共存不成立）。
pub fn bind_to_physical_egress<S: AsFd>(socket: &S) -> Option<String> {
    let iface = physical_egress()?;
    #[cfg(target_os = "linux")]
    {
        match socket2::SockRef::from(socket).bind_device(Some(iface.as_bytes())) {
            Ok(()) => {
                tracing::info!(%iface, "outer traffic bound to physical egress");
                Some(iface)
            }
            Err(error) => {
                tracing::warn!(%iface, %error, "bind socket to physical egress failed");
                None
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        match bound_if_auto(socket, &iface) {
            Ok(()) => {
                tracing::info!(%iface, "outer traffic bound to physical egress");
                Some(iface)
            }
            Err(error) => {
                tracing::warn!(%iface, %error, "bind socket to physical egress failed");
                None
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = socket;
        tracing::debug!(%iface, "socket binding to egress lands with the dataplane");
        None
    }
}

/// `route -n get default` 文本 → 出口网卡名（interface: 行）。
#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_route_get_interface(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim_start)
        .find_map(|line| line.strip_prefix("interface:"))
        .map(|name| name.trim().to_string())
}

/// `netstat -rn -f inet` 文本 → 全部默认路由的网卡名（按出现顺序，
/// 第三方 TUN 类网络工具夺走默认路由时物理网卡通常还在后面的行里）。
#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_netstat_default_ifaces(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| line.split_whitespace().next() == Some("default"))
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            fields.get(3).map(|iface| iface.to_string())
        })
        .collect()
}

/// macOS：默认路由的持有网卡。
#[cfg(target_os = "macos")]
fn egress_from_route_get() -> Option<String> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    parse_route_get_interface(&String::from_utf8_lossy(&output.stdout))
}

/// macOS：默认路由被虚拟网卡夺走时，退到 netstat 路由表里仍持有默认路由
/// 的物理网卡。
#[cfg(target_os = "macos")]
fn egress_from_netstat() -> Option<String> {
    let output = std::process::Command::new("netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .ok()?;
    parse_netstat_default_ifaces(&String::from_utf8_lossy(&output.stdout))
        .into_iter()
        .find(|name| !is_virtual_name(name))
}

/// macOS 的 IP_BOUND_IF / IPV6_BOUND_IF：值是网卡索引（u32）。无需特权。
/// is_v6 决定用 IPV6_BOUND_IF（双栈 v6 socket 上 v4-mapped 流量同样受约束）
/// 还是 IP_BOUND_IF。
#[cfg(target_os = "macos")]
fn bound_if<S: AsFd>(socket: &S, iface: &str, is_v6: bool) -> std::io::Result<()> {
    let name = std::ffi::CString::new(iface).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name has NUL byte",
        )
    })?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (level, option) = if is_v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    };
    let rc = unsafe {
        libc::setsockopt(
            socket.as_fd().as_raw_fd(),
            level,
            option,
            &index as *const libc::c_uint as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// 已绑定的 socket 从本地地址取地址族；未绑定的 socket（连接前的 TCP socket）
/// 没有可查的地址族（Darwin 不实现 SO_DOMAIN），用"只有正确地址族的选项能
/// 设置成功"来判别：先试 IPV6_BOUND_IF，v4 socket 上它会失败，退回 IP_BOUND_IF。
#[cfg(target_os = "macos")]
fn bound_if_auto<S: AsFd>(socket: &S, iface: &str) -> std::io::Result<()> {
    if let Ok(addr) = socket2::SockRef::from(socket).local_addr() {
        return bound_if(socket, iface, addr.is_ipv6());
    }
    if bound_if(socket, iface, true).is_ok() {
        return Ok(());
    }
    bound_if(socket, iface, false)
}

/// `/proc/net/route` 文本 → 结构化条目。地址字段是小端序十六进制。
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_route_table(text: &str) -> Vec<RouteEntry> {
    let mut routes = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let (Some(dest), Some(mask), Ok(metric)) = (
            le_hex_to_ipv4(fields[1]),
            le_hex_to_ipv4(fields[7]),
            fields[6].parse::<u32>(),
        ) else {
            continue;
        };
        routes.push(RouteEntry {
            iface: fields[0].to_string(),
            dest,
            mask,
            metric,
        });
    }
    routes
}

/// "002115AC"（小端）→ 172.21.0.0。
#[cfg(any(target_os = "linux", test))]
fn le_hex_to_ipv4(text: &str) -> Option<Ipv4Addr> {
    let raw = u32::from_str_radix(text, 16).ok()?;
    Some(Ipv4Addr::from(raw.swap_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_with_addr_finds_the_loopback_interface() {
        let iface = interface_with_addr("127.0.0.1".parse().unwrap());
        assert!(
            matches!(iface.as_deref(), Some("lo") | Some("lo0")),
            "127.0.0.1 应属于回环网卡：{iface:?}"
        );
        assert_eq!(interface_with_addr("192.0.2.123".parse().unwrap()), None);
    }

    #[test]
    fn virtual_names_are_excluded_by_prefix() {
        for name in [
            "lo",
            "lo0",
            "tun0",
            "tap9",
            "utun4",
            "docker0",
            "vethab12",
            "br-abcdef",
            "bridge0",
            "ztbuipq1",
            "hz0",
            "awdl0",
            "llw0",
        ] {
            assert!(is_virtual_name(name), "{name} 应被判为虚拟网卡");
        }
        for name in ["eth0", "ens5", "enp0s3", "wlan0", "en0"] {
            assert!(!is_virtual_name(name), "{name} 是物理网卡");
        }
    }

    #[cfg(any(target_os = "macos", test))]
    const ROUTE_GET_ON_VIRTUAL: &str = "   route to: default\n\
         destination: default\n\
                mask: default\n\
           interface: utun4\n\
               flags: <UP,DONE,CLONING,STATIC,GLOBAL>\n\
          recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n\
                0         0         0         0         0         0      4064         0\n";

    #[cfg(any(target_os = "macos", test))]
    const NETSTAT_WITH_VIRTUAL_DEFAULT: &str = "Routing tables\n\n\
         Internet:\n\
         Destination        Gateway            Flags               Netif Expire\n\
         default            link#30            UCSg                utun4\n\
         default            192.168.3.1        UGScIg                en0\n\
         1                  link#30            UCS                 utun4\n\
         10                 192.168.3.1        UGSc                  en0\n\
         127                127.0.0.1          UCS                 lo0\n";

    #[test]
    fn route_get_output_yields_the_interface_line() {
        assert_eq!(
            parse_route_get_interface(ROUTE_GET_ON_VIRTUAL).as_deref(),
            Some("utun4")
        );
        let physical = ROUTE_GET_ON_VIRTUAL.replace("utun4", "en0");
        assert_eq!(
            parse_route_get_interface(&physical).as_deref(),
            Some("en0"),
            "interface: 行有前导空格也要能解析"
        );
        assert_eq!(parse_route_get_interface("no such line"), None);
    }

    #[test]
    fn netstat_defaults_keep_virtual_first_and_physical_second() {
        assert_eq!(
            parse_netstat_default_ifaces(NETSTAT_WITH_VIRTUAL_DEFAULT),
            vec!["utun4".to_string(), "en0".to_string()]
        );
        let picked = parse_netstat_default_ifaces(NETSTAT_WITH_VIRTUAL_DEFAULT)
            .into_iter()
            .find(|name| !is_virtual_name(name));
        assert_eq!(
            picked.as_deref(),
            Some("en0"),
            "第三方 TUN 类网络工具夺走首条默认路由时应退到物理网卡"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bound_if_auto_handles_bound_and_unbound_sockets_of_both_families() {
        let v4 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        bound_if_auto(&v4, "lo0").expect("已绑定 v4 socket：IP_BOUND_IF 到 lo0 应成功");
        let v6 = std::net::UdpSocket::bind("[::1]:0").unwrap();
        bound_if_auto(&v6, "lo0").expect("已绑定 v6 socket：IPV6_BOUND_IF 到 lo0 应成功");

        let unbound_v4 =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        bound_if_auto(&unbound_v4, "lo0").expect("未绑定 v4 socket：v6 选项应失败后 v4 选项成功");
        let unbound_v6 =
            socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None).unwrap();
        bound_if_auto(&unbound_v6, "lo0").expect("未绑定 v6 socket：v6 选项应成功");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bound_if_rejects_unknown_interface_name() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(
            bound_if(&socket, "no-such-iface-x", false).is_err(),
            "不存在的网卡名应报错而不是静默成功"
        );
    }

    #[test]
    fn route_table_parses_little_endian_hex() {
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                     eth0\t000015AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n\
                     eth0\t00000000\t00001501\t0003\t0\t0\t10\t00000000\t0\t0\t0\n";
        let routes = parse_route_table(table);
        assert_eq!(
            routes,
            vec![
                RouteEntry {
                    iface: "eth0".to_string(),
                    dest: "172.21.0.0".parse().unwrap(),
                    mask: "255.255.0.0".parse().unwrap(),
                    metric: 0,
                },
                RouteEntry {
                    iface: "eth0".to_string(),
                    dest: "0.0.0.0".parse().unwrap(),
                    mask: "0.0.0.0".parse().unwrap(),
                    metric: 10,
                },
            ]
        );
    }

    fn entry(iface: &str, dest: &str, mask: &str, metric: u32) -> RouteEntry {
        RouteEntry {
            iface: iface.to_string(),
            dest: dest.parse().unwrap(),
            mask: mask.parse().unwrap(),
            metric,
        }
    }

    #[test]
    fn pick_prefers_lowest_metric_default_on_physical_interface() {
        let routes = vec![
            entry("tun0", "0.0.0.0", "0.0.0.0", 0),
            entry("eth0", "0.0.0.0", "0.0.0.0", 10),
            entry("eth0", "172.21.0.0", "255.255.0.0", 0),
        ];
        assert_eq!(
            pick_egress(&routes, &is_virtual_name).as_deref(),
            Some("eth0")
        );
    }

    #[test]
    fn pick_falls_back_to_subnet_route_when_default_is_virtual() {
        // 第三方 TUN 类网络工具以表外名字夺走默认路由与网段路由；
        // tun_flags 存在性（此处以闭包模拟）仍把它排除，eth0 以网段路由胜出。
        let routes = vec![
            entry("proxytun", "0.0.0.0", "0.0.0.0", 0),
            entry("proxytun", "198.18.0.0", "255.255.255.252", 0),
            entry("hz0", "100.96.0.0", "255.255.0.0", 0),
            entry("eth0", "172.21.0.0", "255.255.0.0", 0),
        ];
        let is_virtual = |name: &str| is_virtual_name(name) || name == "proxytun";
        assert_eq!(pick_egress(&routes, &is_virtual).as_deref(), Some("eth0"));
    }

    #[test]
    fn pick_returns_none_when_everything_is_virtual() {
        let routes = vec![
            entry("tun0", "0.0.0.0", "0.0.0.0", 0),
            entry("docker0", "172.17.0.0", "255.255.0.0", 0),
        ];
        assert_eq!(pick_egress(&routes, &is_virtual_name), None);
    }
}
