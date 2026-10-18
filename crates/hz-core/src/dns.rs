//! 网内名字解析的共享配置（FR-5 / A2）：保留的本地 DNS 应答地址与可配置的
//! 域名后缀。地址固定为 100.96.0.53——不在任何 Node 的分配池里，也不沿用
//! 落在阿里云 100.100.0.0/16 内的地址；后缀默认 hznet.internal，用
//! HZNET_DNS_SUFFIX 覆盖。

use std::net::Ipv4Addr;

/// 本地 DNS 应答绑定的保留地址（A2）；hzd 启动应答时把它作为辅助地址挂到 hz0。
pub const DNS_BIND_V4: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 53);

/// 本地 DNS 应答监听端口。
pub const DNS_PORT: u16 = 53;

/// 网内域名后缀默认值；`<NodeName>.<suffix>` 解析到 Node Address。
pub const DEFAULT_DNS_SUFFIX: &str = "hznet.internal";

/// 读取环境变量 HZNET_DNS_SUFFIX 的后缀配置。
pub fn dns_suffix() -> String {
    dns_suffix_from(std::env::var("HZNET_DNS_SUFFIX").ok().as_deref())
}

/// 纯函数形态的后缀解析：去空白、去首尾圆点、转小写；空值或未设置时用默认后缀。
pub fn dns_suffix_from(value: Option<&str>) -> String {
    value
        .map(|value| value.trim().trim_matches('.').to_lowercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_DNS_SUFFIX.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_normalizes_case_and_trailing_dots() {
        assert_eq!(dns_suffix_from(Some(" Corp.Mesh. ")), "corp.mesh");
        assert_eq!(dns_suffix_from(Some("HZNET.INTERNAL")), "hznet.internal");
    }

    #[test]
    fn suffix_falls_back_to_default_when_missing_or_blank() {
        assert_eq!(dns_suffix_from(None), "hznet.internal");
        assert_eq!(dns_suffix_from(Some("  ..  ")), "hznet.internal");
    }
}
