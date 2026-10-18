//! TUN 设备 hz0：设备创建走 `tun` crate（macOS utun 在 #16 接入），
//! 地址与路由用 `ip` 命令配置。只接管 HzNet 的 IPv4 段（默认 100.96.0.0/16）
//! 与本部署的 ULA /48，绝不路由 100.64.0.0/10（ADR-0003，阿里云内网服务所在段）。
//! `route_args` 是纯函数，可在无 root 的主机上单测路由边界。

use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
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
        ip_args(&["route", "add", &cfg.v4_cidr, "dev", DEVICE_NAME]),
        ip_args(&["-6", "route", "add", &ula48, "dev", DEVICE_NAME]),
    ]
}

fn ip_args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// ULA /48 前缀 = 本机 ULA 地址的前三组。
fn ula_prefix48(addr: Ipv6Addr) -> String {
    let segments = addr.segments();
    format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
}

/// 已创建并配置完毕的 hz0。读循环与写循环共享同一设备句柄。
pub struct Tun {
    #[cfg(target_os = "linux")]
    device: Arc<tun::AsyncDevice>,
}

impl Tun {
    /// 创建 hz0 并接管路由。需要 root 与 /dev/net/tun。
    #[cfg(target_os = "linux")]
    pub fn setup(cfg: &TunConfig) -> anyhow::Result<Self> {
        let mut config = tun::Configuration::default();
        config.name(DEVICE_NAME).mtu(MTU).up();
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

    /// 非 Linux 平台的数据面在 #16 接入；控制面照常工作。
    #[cfg(not(target_os = "linux"))]
    pub fn setup(_cfg: &TunConfig) -> anyhow::Result<Self> {
        bail!("TUN 数据面目前仅支持 Linux；macOS 支持在后续票据实现")
    }

    #[cfg(target_os = "linux")]
    pub fn device(&self) -> Arc<tun::AsyncDevice> {
        self.device.clone()
    }
}

#[cfg(target_os = "linux")]
fn run_ip(args: &[&str]) -> anyhow::Result<()> {
    let output = std::process::Command::new("ip").args(args).output()?;
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
        assert!(joined.contains(&"route add 100.96.0.0/16 dev hz0".to_string()));
        assert!(joined.contains(&"-6 route add fd12:3456:789a::/48 dev hz0".to_string()));
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
        assert!(joined.contains(&"route add 10.200.0.0/16 dev hz0".to_string()));
    }
}
