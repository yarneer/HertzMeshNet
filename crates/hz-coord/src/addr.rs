//! Node Address 分配：可配置的 IPv4 段（默认 100.96.0.0/16）加保留地址表，
//! 外加按部署生成的 ULA /48 IPv6 段（ADR-0003）。

use std::collections::HashSet;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// 100.96.0.53 被 hzd 用作本地 DNS 应答地址（A2），绝不分配给 Node。
pub const RESERVED_DNS_V4: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 53);

/// 默认段（FR-4 / ADR-0003）。cli 与 Default 共用此常量，杜绝第三份写死。
pub const DEFAULT_CIDR: &str = "100.96.0.0/16";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidrV4 {
    network: u32,
    prefix: u8,
}

impl CidrV4 {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let (addr, prefix) = text
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("无效的 CIDR：{text}，期望形如 100.96.0.0/16"))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| anyhow::anyhow!("无效的 CIDR 前缀长度：{prefix}"))?;
        if prefix > 32 {
            anyhow::bail!("CIDR 前缀长度不得超过 32：{prefix}");
        }
        let addr: Ipv4Addr = addr
            .parse()
            .map_err(|_| anyhow::anyhow!("无效的 IPv4 地址：{addr}"))?;
        let mask: u32 = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix as u32)
        };
        Ok(Self {
            network: u32::from(addr) & mask,
            prefix,
        })
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask: u32 = if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix as u32)
        };
        u32::from(ip) & mask == self.network
    }

    fn host_bits(&self) -> u32 {
        32 - self.prefix as u32
    }

    fn host_mask(&self) -> u32 {
        u32::MAX >> self.prefix as u32
    }

    fn network_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }

    fn broadcast_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network | self.host_mask())
    }
}

impl fmt::Display for CidrV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network_addr(), self.prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressConfig {
    pub cidr: CidrV4,
    pub reserved: Vec<Ipv4Addr>,
}

impl Default for AddressConfig {
    fn default() -> Self {
        Self {
            cidr: CidrV4::parse(DEFAULT_CIDR).expect("默认段常量必须合法"),
            reserved: vec![RESERVED_DNS_V4],
        }
    }
}

impl AddressConfig {
    /// 序列化到 meta 表的规范形：CIDR + 逗号分隔的额外保留地址（不含推导的 DNS）。
    pub fn meta_repr(&self) -> (String, Vec<String>) {
        let extras: Vec<String> = self
            .reserved
            .iter()
            .filter(|ip| **ip != self.reserved_dns())
            .map(|ip| ip.to_string())
            .collect();
        (self.cidr.to_string(), extras)
    }

    /// 部署级校验：段必须容纳段内 DNS 应答地址（A2 推广）。分配器本身
    /// 支持任意前缀（穷尽测试依赖 /30），此约束属于配置入口的策略。
    pub fn validate_for_deployment(&self) -> anyhow::Result<()> {
        if self.cidr.host_bits() < 7 || !self.cidr.contains(self.reserved_dns()) {
            anyhow::bail!(
                "地址段 {cidr} 过小：至少 /25（为段内 DNS 应答地址与余量）",
                cidr = self.cidr
            );
        }
        Ok(())
    }

    /// 从 meta 表恢复；extra 为额外保留地址。
    pub fn from_meta(cidr: &str, extras: &[String]) -> anyhow::Result<Self> {
        let reserved: Vec<Ipv4Addr> = extras
            .iter()
            .filter(|text| !text.is_empty())
            .map(|text| {
                text.parse()
                    .map_err(|_| anyhow::anyhow!("无效的保留地址：{text}"))
            })
            .collect::<anyhow::Result<_>>()?;
        Self::parse(cidr, &reserved)
    }
}

/// 段内 DNS 应答地址：网络基址低位置 53（A2 的推广）。默认段 100.96.0.0/16
/// 推导出规格固定的 100.96.0.53；改段后随之落在段内，hzd 与坐标各自独立
/// 推导必得同值。要求段至少 /25（host_bits ≥ 7）才能容纳。
pub fn reserved_dns_for(cidr: &CidrV4) -> Ipv4Addr {
    Ipv4Addr::from(cidr.network | 53)
}

impl AddressConfig {
    pub fn parse(cidr: &str, reserved: &[Ipv4Addr]) -> anyhow::Result<Self> {
        let cidr = CidrV4::parse(cidr)?;
        let mut reserved = reserved.to_vec();
        for ip in &reserved {
            if !cidr.contains(*ip) {
                anyhow::bail!("保留地址 {ip} 不在段 {cidr} 内");
            }
        }
        let dns = reserved_dns_for(&cidr);
        if cidr.contains(dns) && !reserved.contains(&dns) {
            reserved.push(dns);
        }
        Ok(Self { cidr, reserved })
    }

    /// 当前段推导的 DNS 应答地址（下发给 Node）。
    pub fn reserved_dns(&self) -> Ipv4Addr {
        reserved_dns_for(&self.cidr)
    }

    pub fn is_assignable(&self, ip: Ipv4Addr) -> bool {
        if !self.cidr.contains(ip) || self.reserved.contains(&ip) {
            return false;
        }
        // 前缀 <=30 时网络地址与广播地址不可用；/31、/32 无此概念。
        if self.cidr.host_bits() >= 2
            && (ip == self.cidr.network_addr() || ip == self.cidr.broadcast_addr())
        {
            return false;
        }
        true
    }

    /// 取段内最低的可用且未占用的地址；全段耗尽返回 None。
    pub fn allocate(&self, taken: &HashSet<Ipv4Addr>) -> Option<Ipv4Addr> {
        let first = if self.cidr.host_bits() >= 2 {
            self.cidr.network + 1
        } else {
            self.cidr.network
        };
        let last = if self.cidr.host_bits() >= 2 {
            u32::from(self.cidr.broadcast_addr()) - 1
        } else {
            u32::from(self.cidr.broadcast_addr())
        };
        for raw in first..=last {
            let ip = Ipv4Addr::from(raw);
            if self.is_assignable(ip) && !taken.contains(&ip) {
                return Some(ip);
            }
        }
        None
    }
}

/// ULA /48 前缀（fd + 40 随机位）转换成每 Node 的 /128：
/// 前缀三组 + 三个 0 组 + v4 地址的 32 位作为低两组，保证从 v4 单射可得。
pub fn ula_ipv6(prefix: [u8; 6], v4: Ipv4Addr) -> Ipv6Addr {
    let v4_bits = u32::from(v4);
    Ipv6Addr::new(
        u16::from_be_bytes([prefix[0], prefix[1]]),
        u16::from_be_bytes([prefix[2], prefix[3]]),
        u16::from_be_bytes([prefix[4], prefix[5]]),
        0,
        0,
        0,
        (v4_bits >> 16) as u16,
        (v4_bits & 0xffff) as u16,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alloc_seq(cfg: &AddressConfig, count: usize) -> Vec<Ipv4Addr> {
        let mut taken = HashSet::new();
        let mut out = Vec::new();
        for _ in 0..count {
            let ip = cfg.allocate(&taken).expect("地址段内应有可用地址");
            taken.insert(ip);
            out.push(ip);
        }
        out
    }

    #[test]
    fn default_range_never_yields_reserved_network_or_broadcast() {
        let cfg = AddressConfig::default();
        for ip in alloc_seq(&cfg, 300) {
            assert_ne!(
                ip, RESERVED_DNS_V4,
                "100.96.0.53 保留给本地 DNS 应答，不得分配"
            );
            assert_ne!(ip, Ipv4Addr::new(100, 96, 0, 0), "网络地址不得分配");
            assert_ne!(ip, Ipv4Addr::new(100, 96, 255, 255), "广播地址不得分配");
            assert!(cfg.cidr.contains(ip));
        }
    }

    #[test]
    fn allocations_are_distinct_and_start_low() {
        let ips = alloc_seq(&AddressConfig::default(), 3);
        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(100, 96, 0, 1),
                Ipv4Addr::new(100, 96, 0, 2),
                Ipv4Addr::new(100, 96, 0, 3),
            ]
        );
    }

    #[test]
    fn custom_small_cidr_exhausts_with_clear_none() {
        let cfg = AddressConfig::parse("100.96.0.0/30", &[]).unwrap();
        let mut taken = HashSet::new();
        let a = cfg.allocate(&taken).unwrap();
        taken.insert(a);
        let b = cfg.allocate(&taken).unwrap();
        taken.insert(b);
        assert_eq!(a, Ipv4Addr::new(100, 96, 0, 1));
        assert_eq!(b, Ipv4Addr::new(100, 96, 0, 2));
        assert!(
            cfg.allocate(&taken).is_none(),
            "/30 只含两个可分配地址，第三次应耗尽"
        );
    }

    #[test]
    fn reserved_dns_derives_from_the_active_range() {
        assert_eq!(
            reserved_dns_for(&CidrV4::parse("100.96.0.0/16").unwrap()),
            RESERVED_DNS_V4,
            "默认段的推导值必须与规格 A2 固定的 100.96.0.53 一致"
        );
        assert_eq!(
            reserved_dns_for(&CidrV4::parse("100.110.0.0/16").unwrap()),
            Ipv4Addr::new(100, 110, 0, 53)
        );
        assert_eq!(
            reserved_dns_for(&CidrV4::parse("10.44.0.0/24").unwrap()),
            Ipv4Addr::new(10, 44, 0, 53)
        );
    }

    #[test]
    fn custom_range_reserves_its_derived_dns_address() {
        let cfg =
            AddressConfig::parse("100.110.0.0/24", &["100.110.0.7".parse().unwrap()]).unwrap();
        let mut taken = HashSet::new();
        for _ in 0..252 {
            let ip = cfg.allocate(&taken).expect("段内应有可用地址");
            assert_ne!(
                ip,
                Ipv4Addr::new(100, 110, 0, 53),
                "段内推导的 DNS 保留地址不得分配"
            );
            assert_ne!(
                ip,
                Ipv4Addr::new(100, 110, 0, 7),
                "--reserve 指定的地址不得分配"
            );
            taken.insert(ip);
        }
        assert!(
            cfg.allocate(&taken).is_none(),
            "/24 的 254 个可用地址减去两个保留后恰好用尽"
        );
    }

    #[test]
    fn ula_is_parseable_and_injective_over_v4() {
        let prefix = [0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a];
        let a = ula_ipv6(prefix, Ipv4Addr::new(100, 96, 0, 10));
        let b = ula_ipv6(prefix, Ipv4Addr::new(100, 96, 0, 11));
        let a2 = ula_ipv6(prefix, Ipv4Addr::new(100, 96, 0, 10));
        assert_eq!(
            a.to_string().parse::<Ipv6Addr>().unwrap(),
            a,
            "必须可解析回自身"
        );
        assert_ne!(a, b);
        assert_eq!(a, a2);
        assert!(a.segments()[0] >> 8 == 0xfd);
        // 低 32 位 = v4 的 32 位：100.96.0.10 = 0x6460000a
        assert_eq!(a.segments()[6], 0x6460);
        assert_eq!(a.segments()[7], 0x000a);
    }

    #[test]
    fn cidr_parse_rejects_garbage() {
        assert!(CidrV4::parse("100.96.0.0").is_err());
        assert!(CidrV4::parse("100.96.0.0/33").is_err());
        assert!(CidrV4::parse("not-an-ip/16").is_err());
        assert!(CidrV4::parse("100.96.0.0/16").is_ok());
    }
}
