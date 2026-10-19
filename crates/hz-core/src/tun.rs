//! TUN 设备：Linux 上是 hz0（`ip` 命令配置），macOS 上是内核分配的 utun
//! （`ifconfig`/`route` 命令配置，名字创建后才可知）。只接管 HzNet 的 IPv4 段
//! （默认 100.96.0.0/16）与本部署的 ULA /48，绝不路由 100.64.0.0/10
//! （ADR-0003，阿里云内网服务所在段）。`route_args`/`macos_config_args`
//! 是纯函数，可在无 root 的主机上单测路由边界。

use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::sync::OnceLock;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;
use anyhow::bail;

pub const DEVICE_NAME: &str = "hz0";
pub const MTU: u16 = 1280;

/// HzNet 默认 IPv4 段；与 Coordination Server 的 AddressConfig 默认一致。
/// 部署改段时用 HZD_V4_CIDR 覆盖（两端必须同段）。
pub const DEFAULT_V4_CIDR: &str = "100.96.0.0/16";

/// 绝不接管的 CGNAT 大段（ADR-0003）。路由表里出现它就是回归。
pub const FORBIDDEN_CIDR: &str = "100.64.0.0/10";

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    /// HzNet IPv4 段（CIDR）。
    pub v4_cidr: String,
}

/// 计算配置 hz0 需要的全部 `ip` 命令参数序列。
/// 点对点 /32 + /128 地址，路由只挂 HzNet v4 段与 ULA /48。
pub fn route_args(cfg: &TunConfig) -> Vec<Vec<String>> {
    let ula48 = ula_prefix48(cfg.ipv6);
    vec![
        ip_args(&["link", "set", DEVICE_NAME, "mtu", &MTU.to_string(), "up"]),
        ip_args(&[
            "addr",
            "add",
            &format!("{}/32", cfg.ipv4),
            "dev",
            DEVICE_NAME,
        ]),
        ip_args(&[
            "-6",
            "addr",
            "add",
            &format!("{}/128", cfg.ipv6),
            "dev",
            DEVICE_NAME,
            "nodad",
        ]),
        // replace 幂等：设备/路由残留（如快速重启）不会让 setup 失败。
        ip_args(&["route", "replace", &cfg.v4_cidr, "dev", DEVICE_NAME]),
        ip_args(&["-6", "route", "replace", &ula48, "dev", DEVICE_NAME]),
    ]
}

fn ip_args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// 在 hz0 上追加/移除一个辅助 /32 地址（如保留的本地 DNS 应答地址）的
/// `ip` 命令参数；纯函数，可在无 root 主机上单测。
pub fn secondary_addr_args(addr: &Ipv4Addr, add: bool) -> Vec<String> {
    let action = if add { "add" } else { "del" };
    ip_args(&["addr", action, &format!("{addr}/32"), "dev", DEVICE_NAME])
}

/// 给 hz0 追加辅助地址。地址已存在（EEXIST）视为成功——重复启动幂等。
#[cfg(target_os = "linux")]
pub fn add_secondary_addr(addr: &Ipv4Addr) -> anyhow::Result<()> {
    let args = secondary_addr_args(addr, true);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match run_ip(&refs) {
        Ok(()) => Ok(()),
        Err(error) if error.to_string().contains("File exists") => Ok(()),
        Err(error) => Err(error),
    }
}

/// 从 hz0 移除辅助地址。地址本来不存在也视为成功——清理路径幂等。
#[cfg(target_os = "linux")]
pub fn remove_secondary_addr(addr: &Ipv4Addr) -> anyhow::Result<()> {
    let args = secondary_addr_args(addr, false);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match run_ip(&refs) {
        Ok(()) => Ok(()),
        Err(error)
            if error
                .to_string()
                .contains("Cannot assign requested address") =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// 非 Linux 平台 hz0 尚未落地（#16），辅助地址同样不可用。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn add_secondary_addr(_addr: &Ipv4Addr) -> anyhow::Result<()> {
    bail!("hz0 辅助地址目前仅支持 Linux/macOS；其他平台在后续票据实现")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn remove_secondary_addr(_addr: &Ipv4Addr) -> anyhow::Result<()> {
    bail!("hz0 辅助地址目前仅支持 Linux/macOS；其他平台在后续票据实现")
}

/// ULA /48 前缀 = 本机 ULA 地址的前三组。
fn ula_prefix48(addr: Ipv6Addr) -> String {
    let segments = addr.segments();
    format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
}

/// macOS：本进程创建的 utun 设备名（内核分配，如 utun9）。
/// 辅助地址（本地 DNS 应答的 100.96.0.53）挂靠它，DNS 启动晚于 TUN，
/// 用进程级槽位传递而不是穿过 IPC。
#[cfg(target_os = "macos")]
static MAC_IFACE: OnceLock<String> = OnceLock::new();

/// 计算配置 macOS utun 需要的全部命令参数序列（首元素是程序名）。
/// 点对点地址（本机地址兼任对端），路由只挂 HzNet v4 段与 ULA /48。
#[cfg(target_os = "macos")]
pub fn macos_config_args(cfg: &TunConfig, iface: &str) -> Vec<Vec<String>> {
    let ula48 = ula_prefix48(cfg.ipv6);
    vec![
        cmd_args(
            "ifconfig",
            &[iface, &cfg.ipv4.to_string(), &cfg.ipv4.to_string(), "up"],
        ),
        cmd_args("ifconfig", &[iface, "mtu", &MTU.to_string()]),
        cmd_args(
            "ifconfig",
            &[iface, "inet6", &format!("{}/128", cfg.ipv6), "add"],
        ),
        // utun 名字每次创建都变（utun8→utun9→…），旧实例残留的同段路由会让
        // add 报 File exists；先删后加保证幂等（delete 对不存在的路由报错，
        // setup 里对 delete 一类命令容忍失败）。
        cmd_args("route", &["-n", "delete", "-net", &cfg.v4_cidr]),
        cmd_args(
            "route",
            &["-n", "add", "-net", &cfg.v4_cidr, "-interface", iface],
        ),
        cmd_args("route", &["-n", "delete", "-inet6", &ula48]),
        cmd_args(
            "route",
            &["-n", "add", "-inet6", &ula48, "-interface", iface],
        ),
    ]
}

#[cfg(target_os = "macos")]
fn cmd_args(program: &str, parts: &[&str]) -> Vec<String> {
    std::iter::once(program.to_string())
        .chain(parts.iter().map(|s| s.to_string()))
        .collect()
}

/// macOS 上给 utun 追加/移除辅助地址（如本地 DNS 应答地址）的命令参数。
#[cfg(target_os = "macos")]
pub fn macos_secondary_alias_args(iface: &str, addr: &Ipv4Addr, add: bool) -> Vec<String> {
    let action = if add { "add" } else { "remove" };
    cmd_args(
        "ifconfig",
        &[iface, &addr.to_string(), &addr.to_string(), action],
    )
}

/// macOS：给 utun 追加辅助地址。地址已存在视为成功——重复启动幂等。
/// 数据面（Tun::setup）未拉起时没有可挂靠的 utun，直接失败。
#[cfg(target_os = "macos")]
pub fn add_secondary_addr(addr: &Ipv4Addr) -> anyhow::Result<()> {
    let iface = MAC_IFACE.get().ok_or_else(|| {
        anyhow::anyhow!("utun 数据面未创建，无法挂辅助地址 {addr}（数据面需要 root 权限）")
    })?;
    let args = macos_secondary_alias_args(iface, addr, true);
    run_macos_cmd(&args)
}

/// macOS：从 utun 移除辅助地址。地址本来不存在也视为成功——清理路径幂等。
#[cfg(target_os = "macos")]
pub fn remove_secondary_addr(addr: &Ipv4Addr) -> anyhow::Result<()> {
    let Some(iface) = MAC_IFACE.get() else {
        return Ok(());
    };
    let args = macos_secondary_alias_args(iface, addr, false);
    run_macos_cmd(&args).or_else(|error| {
        // alias 不存在时 ifconfig 报 can't address unresolved destination 之类的错。
        if error.to_string().contains("can't address")
            || error.to_string().contains("does not seem to be")
        {
            Ok(())
        } else {
            Err(error)
        }
    })
}

#[cfg(target_os = "macos")]
fn run_macos_cmd(args: &[String]) -> anyhow::Result<()> {
    let output = std::process::Command::new(&args[0])
        .args(&args[1..])
        .output()
        .with_context(|| format!("execute {} 失败（命令不存在？）", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "{} 失败：{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// 已创建并配置完毕的 TUN 设备。读循环与写循环共享同一设备句柄。
pub struct Tun {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    device: Arc<tun::AsyncDevice>,
}

impl Tun {
    /// 创建 hz0 并接管路由。需要 root 与 /dev/net/tun。
    #[cfg(target_os = "linux")]
    pub fn setup(cfg: &TunConfig) -> anyhow::Result<Self> {
        let mut config = tun::Configuration::default();
        config.tun_name(DEVICE_NAME).mtu(MTU).up();
        let device = tun::create_as_async(&config)
            .with_context(|| format!("create tun device {DEVICE_NAME} failed"))?;

        for args in route_args(cfg) {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            run_ip(&refs)?;
        }
        tracing::info!(
            ipv4 = %cfg.ipv4,
            ipv6 = %cfg.ipv6,
            v4_cidr = %cfg.v4_cidr,
            "tun device hz0 configured"
        );
        Ok(Self {
            device: Arc::new(device),
        })
    }

    /// 创建 utun 并接管路由（设备名由内核分配）。需要 root；
    /// 无 root 时内核对 utun 控制socket 返回 EPERM，这里给出明确提示。
    #[cfg(target_os = "macos")]
    pub fn setup(cfg: &TunConfig) -> anyhow::Result<Self> {
        let mut config = tun::Configuration::default();
        // utun 名字带内核分配的序号，不能像 Linux 那样指定 hz0。
        config.mtu(MTU);
        let device = tun::create_as_async(&config).map_err(|error| {
            if error.to_string().contains("os error 1") || error.to_string().contains("EPERM") {
                anyhow::anyhow!(
                    "创建 utun 设备需要 root 权限（以 sudo 运行或经 launchd 安装）：{error}"
                )
            } else {
                anyhow::anyhow!("create utun device failed: {error}")
            }
        })?;
        use tun::AbstractDevice as _;
        let iface = device
            .tun_name()
            .with_context(|| "query utun device name failed")?;
        for args in macos_config_args(cfg, &iface) {
            // route delete 清残留时路由本就不存在是常态，失败不致命；
            // 其余命令失败仍视为 setup 失败。
            if args.get(1).is_some_and(|sub| sub == "delete") {
                let _ = run_macos_cmd(&args);
            } else {
                run_macos_cmd(&args)?;
            }
        }
        let _ = MAC_IFACE.set(iface.clone());
        tracing::info!(
            iface = %iface,
            ipv4 = %cfg.ipv4,
            ipv6 = %cfg.ipv6,
            v4_cidr = %cfg.v4_cidr,
            "utun device configured"
        );
        Ok(Self {
            device: Arc::new(device),
        })
    }

    /// 其余平台的数据面尚未落地；控制面照常工作。
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub fn setup(_cfg: &TunConfig) -> anyhow::Result<Self> {
        bail!("TUN 数据面目前仅支持 Linux/macOS；其他平台在后续票据实现")
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn device(&self) -> Arc<tun::AsyncDevice> {
        self.device.clone()
    }
}

#[cfg(target_os = "linux")]
fn run_ip(args: &[&str]) -> anyhow::Result<()> {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("execute ip {} (iproute2 未安装？)", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "ip {} 失败：{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> TunConfig {
        TunConfig {
            ipv4: Ipv4Addr::new(100, 96, 0, 1),
            ipv6: "fd12:3456:789a::6460:1".parse().unwrap(),
            v4_cidr: DEFAULT_V4_CIDR.to_string(),
        }
    }

    #[test]
    fn routes_cover_only_hznet_v4_cidr_and_own_ula() {
        let args = route_args(&config());
        let joined: Vec<String> = args.iter().map(|a| a.join(" ")).collect();
        assert!(joined.contains(&"route replace 100.96.0.0/16 dev hz0".to_string()));
        assert!(joined.contains(&"-6 route replace fd12:3456:789a::/48 dev hz0".to_string()));
        assert!(
            joined.contains(&"addr add 100.96.0.1/32 dev hz0".to_string()),
            "本机 v4 地址必须是点对点 /32：{joined:?}"
        );
    }

    #[test]
    fn routes_never_capture_the_wider_cgnat_range() {
        for args in route_args(&config()) {
            assert!(
                !args.iter().any(|a| a.contains(FORBIDDEN_CIDR)),
                "不得把 {FORBIDDEN_CIDR} 路由进 hz0：{args:?}"
            );
        }
    }

    #[test]
    fn custom_v4_cidr_is_honored() {
        let cfg = TunConfig {
            v4_cidr: "10.200.0.0/16".to_string(),
            ..config()
        };
        let joined: Vec<String> = route_args(&cfg).iter().map(|a| a.join(" ")).collect();
        assert!(joined.contains(&"route replace 10.200.0.0/16 dev hz0".to_string()));
    }

    #[test]
    fn secondary_addr_is_point_to_point_on_hz0() {
        assert_eq!(
            secondary_addr_args(&Ipv4Addr::new(100, 96, 0, 53), true).join(" "),
            "addr add 100.96.0.53/32 dev hz0"
        );
        assert_eq!(
            secondary_addr_args(&Ipv4Addr::new(100, 96, 0, 53), false).join(" "),
            "addr del 100.96.0.53/32 dev hz0"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_config_args_configure_addresses_mtu_and_only_hznet_routes() {
        let args = macos_config_args(&config(), "utun9");
        let joined: Vec<String> = args.iter().map(|a| a.join(" ")).collect();
        assert_eq!(
            joined[0], "ifconfig utun9 100.96.0.1 100.96.0.1 up",
            "点对点：本机地址兼任对端"
        );
        assert_eq!(joined[1], "ifconfig utun9 mtu 1280");
        assert_eq!(
            joined[2],
            "ifconfig utun9 inet6 fd12:3456:789a::6460:1/128 add"
        );
        assert_eq!(joined[3], "route -n delete -net 100.96.0.0/16");
        assert_eq!(
            joined[4],
            "route -n add -net 100.96.0.0/16 -interface utun9"
        );
        assert_eq!(joined[5], "route -n delete -inet6 fd12:3456:789a::/48");
        assert_eq!(
            joined[6],
            "route -n add -inet6 fd12:3456:789a::/48 -interface utun9"
        );
        assert_eq!(joined.len(), 7, "不得有多余命令：{joined:?}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_config_args_never_capture_the_wider_cgnat_range() {
        for args in macos_config_args(&config(), "utun9") {
            assert!(
                !args.iter().any(|a| a.contains(FORBIDDEN_CIDR)),
                "不得把 {FORBIDDEN_CIDR} 路由进 utun：{args:?}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_config_args_honor_custom_v4_cidr() {
        let cfg = TunConfig {
            v4_cidr: "10.200.0.0/16".to_string(),
            ..config()
        };
        let joined: Vec<String> = macos_config_args(&cfg, "utun3")
            .iter()
            .map(|a| a.join(" "))
            .collect();
        assert!(joined.contains(&"route -n delete -net 10.200.0.0/16".to_string()));
        assert!(joined.contains(&"route -n add -net 10.200.0.0/16 -interface utun3".to_string()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_secondary_alias_adds_and_removes_on_the_utun() {
        assert_eq!(
            macos_secondary_alias_args("utun9", &Ipv4Addr::new(100, 96, 0, 53), true).join(" "),
            "ifconfig utun9 100.96.0.53 100.96.0.53 add"
        );
        assert_eq!(
            macos_secondary_alias_args("utun9", &Ipv4Addr::new(100, 96, 0, 53), false).join(" "),
            "ifconfig utun9 100.96.0.53 100.96.0.53 remove"
        );
    }
}
