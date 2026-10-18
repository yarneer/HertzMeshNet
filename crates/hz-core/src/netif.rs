//! 隧道外层流量的物理出口网卡（FR-7 与第三方 TUN 类网络工具共存）。
//! hzd 的全部外层流量（WireGuard/打洞 UDP、到 Coordination Server 的连接）
//! 在创建 socket 时就绑到物理出口网卡，不进入接管默认路由的虚拟网卡。
//! Linux 用 SO_BINDTODEVICE；macOS 的 IP_BOUND_IF（`bind_device_by_index_v4/v6`）
//! 随 macOS 数据面票据接入。出口变化后的重绑不在本模块（见 #9/#16）。

#[cfg(any(target_os = "linux", test))]
use std::net::Ipv4Addr;
use std::os::fd::AsFd;

/// 虚拟网卡的名称前缀排除表。第三方 TUN 类网络工具可能用表外名字创建
/// tun 设备，Linux 上另用 `/sys/class/net/<if>/tun_flags` 的存在性兜底。
const VIRTUAL_NAME_PREFIXES: &[&str] = &[
    "lo", "tun", "tap", "hz", "utun", "docker", "veth", "br-", "bridge", "zt",
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

/// 当前物理出口网卡。探测不到（非 Linux、无路由表、全是虚拟网卡）返回 None。
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
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// 把 socket 绑到物理出口网卡（Linux SO_BINDTODEVICE，须在 connect(2) 之前生效）。
/// 返回绑定的网卡名；探测或设置失败时返回 None，外层流量退回系统路由并记录告警
/// （此时与第三方 TUN 类网络工具的共存不成立）。
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
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket;
        tracing::debug!(%iface, "socket binding to egress lands with the macOS dataplane");
        None
    }
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
        ] {
            assert!(is_virtual_name(name), "{name} 应被判为虚拟网卡");
        }
        for name in ["eth0", "ens5", "enp0s3", "wlan0", "en0"] {
            assert!(!is_virtual_name(name), "{name} 是物理网卡");
        }
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
