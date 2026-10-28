//! 端口映射（#77）：依次尝试 PCP（RFC 6887）、NAT-PMP（RFC 6886）、
//! UPnP IGD（SSDP 发现 + `AddPortMapping` SOAP），为 WireGuard 共享 UDP 端口
//! 申请稳定公网映射，作为 `PortMap` 候选上报（优先级高于 Stun）。
//! 映射返回的外网地址是私网 / CGNAT / 198.18.0.0/15 时判定为多重 NAT，
//! 不上报该候选，netcheck 提示把光猫改桥接。
//!
//! 报文编解码是纯函数（表驱动单测）；网络交互经物理出口网卡（FR-7），
//! 网关为回环（进程内测试桩）时不绑——绑了物理网卡就到不了回环。

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, bail};
use rand_core::{OsRng, RngCore};

/// PCP 与 NAT-PMP 的 UDP 端口。
pub const GATEWAY_PORT: u16 = 5351;
/// SSDP 组播端点。
const SSDP_MULTICAST: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)),
    1900,
);
/// 单个协议尝试的应答等待；三个协议加 SSDP 的总预算控制在 ~10 秒。
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
/// UPnP 映射的租期：续租循环在半程续；hzd 退出时尽力删除，删不掉的靠它过期。
pub const UPNP_LEASE_SECS: u32 = 3600;

/// 申请到的映射协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMapProtocol {
    Pcp,
    NatPmp,
    Upnp,
}

impl PortMapProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            PortMapProtocol::Pcp => "PCP",
            PortMapProtocol::NatPmp => "NAT-PMP",
            PortMapProtocol::Upnp => "UPnP",
        }
    }
}

/// 外网地址分类（#77 多重 NAT 判定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalClass {
    /// 公网地址：映射可用。
    Public,
    /// RFC1918 / 回环 / 链路本地：路由器上游还有 NAT。
    Private,
    /// 100.64.0.0/10 运营商级 NAT：上游还有运营商 NAT。
    Cgnat,
    /// 198.18.0.0/15 基准测试网段（也可能被第三方 TUN 工具占用）。
    Benchmark,
}

impl ExternalClass {
    pub fn is_public(self) -> bool {
        matches!(self, ExternalClass::Public)
    }
}

/// IPv4 外网地址分类。端口映射只走 IPv4（NAT-PMP/PCP 请求的是 v4 映射）。
pub fn classify_external(ip: Ipv4Addr) -> ExternalClass {
    let [a, b, ..] = ip.octets();
    match (a, b) {
        (10, _) => ExternalClass::Private,
        (172, 16..=31) => ExternalClass::Private,
        (192, 168) => ExternalClass::Private,
        (169, 254) => ExternalClass::Private,
        (127, _) => ExternalClass::Private,
        (0, _) => ExternalClass::Private,
        (100, 64..=127) => ExternalClass::Cgnat,
        (198, 18 | 19) => ExternalClass::Benchmark,
        _ => ExternalClass::Public,
    }
}

/// 一份生效的映射租约。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapLease {
    pub protocol: PortMapProtocol,
    pub gateway: SocketAddr,
    pub internal_port: u16,
    pub external: SocketAddr,
    pub lifetime_secs: u32,
    /// UPnP 的 (control URL, serviceType)——续租/删除的 SOAP 必须用发现的
    /// serviceType（WANIPConnection:1/:2 或 WANPPPConnection:1）作命名空间；
    /// PCP/NAT-PMP 为 None。
    pub upnp: Option<(String, String)>,
    /// PCP 的 nonce：续租保持不变，网关才延续同一映射（外端口不漂移）。
    pub pcp_nonce: [u8; 12],
}

/// 一次映射申请的结局。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingOutcome {
    /// 拿到公网映射：上报 `PortMap` 候选。
    Mapped(PortMapLease),
    /// 映射成功但外网地址不是公网：多重 NAT，不上报，netcheck 提示。
    MultiNat {
        protocol: PortMapProtocol,
        external: Ipv4Addr,
    },
}

// ---------------------------------------------------------------------------
// NAT-PMP（RFC 6886）
// ---------------------------------------------------------------------------

/// NAT-PMP 报文编解码。请求：ver=0 + opcode；应答：ver=0 + opcode|0x80。
pub mod natpmp {
    use std::net::Ipv4Addr;

    pub const RESULT_SUCCESS: u16 = 0;

    /// 查询外网地址：`[0x00, 0x00]`。
    pub fn external_addr_request() -> [u8; 2] {
        [0, 0]
    }

    /// 申请 UDP 端口映射（12 字节）。lifetime=0 表示删除既有映射。
    pub fn map_udp_request(
        internal_port: u16,
        suggested_external: u16,
        lifetime_secs: u32,
    ) -> [u8; 12] {
        let mut message = [0u8; 12];
        message[0] = 0; // version
        message[1] = 2; // opcode: MAP UDP
        // [2..4] reserved
        message[4..6].copy_from_slice(&internal_port.to_be_bytes());
        message[6..8].copy_from_slice(&suggested_external.to_be_bytes());
        message[8..12].copy_from_slice(&lifetime_secs.to_be_bytes());
        message
    }

    pub struct ExternalAddrResponse {
        pub result: u16,
        pub external: Ipv4Addr,
    }

    /// 外网地址应答（12 字节）：ver, opcode(0x80), result(2), epoch(4), ip(4)。
    pub fn parse_external_addr_response(message: &[u8]) -> Option<ExternalAddrResponse> {
        if message.len() < 12 || message[0] != 0 || message[1] != 0x80 {
            return None;
        }
        Some(ExternalAddrResponse {
            result: u16::from_be_bytes([message[2], message[3]]),
            external: Ipv4Addr::new(message[8], message[9], message[10], message[11]),
        })
    }

    pub struct MapResponse {
        pub result: u16,
        pub internal_port: u16,
        pub external_port: u16,
        pub lifetime_secs: u32,
    }

    /// 端口映射应答（16 字节）：ver, opcode(0x82), result(2), epoch(4),
    /// internal(2), external(2), lifetime(4)。
    pub fn parse_map_response(message: &[u8]) -> Option<MapResponse> {
        if message.len() < 16 || message[0] != 0 || message[1] != 0x82 {
            return None;
        }
        Some(MapResponse {
            result: u16::from_be_bytes([message[2], message[3]]),
            internal_port: u16::from_be_bytes([message[8], message[9]]),
            external_port: u16::from_be_bytes([message[10], message[11]]),
            lifetime_secs: u32::from_be_bytes([message[12], message[13], message[14], message[15]]),
        })
    }
}

// ---------------------------------------------------------------------------
// PCP（RFC 6887）
// ---------------------------------------------------------------------------

/// PCP MAP 报文编解码。公共头 24 字节 + MAP 载荷 36 字节。
pub mod pcp {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    pub const VERSION: u8 = 2;
    pub const OPCODE_MAP: u8 = 1;
    pub const PROTOCOL_UDP: u8 = 17;
    pub const RESULT_SUCCESS: u8 = 0;

    fn zero_ipv4_mapped() -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[10] = 0xff;
        addr[11] = 0xff;
        addr
    }

    fn ipv4_mapped(ip: Ipv4Addr) -> [u8; 16] {
        let mut addr = zero_ipv4_mapped();
        addr[12..16].copy_from_slice(&ip.octets());
        addr
    }

    /// MAP 请求（60 字节）。external_port=0 且 lifetime>0 表示"任意外端口"；
    /// lifetime=0 表示删除。
    pub fn map_request(
        nonce: [u8; 12],
        internal_port: u16,
        external_port: u16,
        lifetime_secs: u32,
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(60);
        message.push(VERSION);
        message.push(OPCODE_MAP);
        message.extend_from_slice(&[0u8; 2]); // reserved
        message.extend_from_slice(&lifetime_secs.to_be_bytes());
        message.extend_from_slice(&zero_ipv4_mapped()); // client addr（0.0.0.0）
        message.extend_from_slice(&nonce);
        message.push(PROTOCOL_UDP);
        message.extend_from_slice(&[0u8; 3]); // reserved
        message.extend_from_slice(&internal_port.to_be_bytes());
        message.extend_from_slice(&ipv4_mapped(Ipv4Addr::UNSPECIFIED)); // 期望外网地址
        message.extend_from_slice(&external_port.to_be_bytes());
        message
    }

    pub struct MapResponse {
        pub result: u8,
        pub lifetime_secs: u32,
        pub internal_port: u16,
        pub external: SocketAddr,
    }

    /// MAP 应答（60 字节）：公共头（result 1B + lifetime 4B + epoch 4B +
    /// reserved 12B）后接 MAP 载荷（nonce 12B、protocol 1B、reserved 3B、
    /// internal port 2B、external addr 16B、external port 2B）。
    pub fn parse_map_response(message: &[u8]) -> Option<MapResponse> {
        if message.len() < 60 || message[0] != VERSION || message[1] != OPCODE_MAP | 0x80 {
            return None;
        }
        let result = message[3];
        let lifetime_secs = u32::from_be_bytes([message[4], message[5], message[6], message[7]]);
        let internal_port = u16::from_be_bytes([message[40], message[41]]);
        let external_port = u16::from_be_bytes([message[58], message[59]]);
        let mapped_octets: [u8; 16] = message[42..58]
            .try_into()
            .expect("60 字节应答的 42..58 必然是 16 字节");
        let external = match Ipv6Addr::from(mapped_octets).to_canonical() {
            std::net::IpAddr::V4(v4) => SocketAddr::new(std::net::IpAddr::V4(v4), external_port),
            std::net::IpAddr::V6(v6) => SocketAddr::new(std::net::IpAddr::V6(v6), external_port),
        };
        Some(MapResponse {
            result,
            lifetime_secs,
            internal_port,
            external,
        })
    }
}

// ---------------------------------------------------------------------------
// UPnP IGD（SSDP + SOAP）
// ---------------------------------------------------------------------------

/// UPnP 的 SSDP 发现与 SOAP 交互。XML 用手写的标签扫描（与仓库"手写协议、
/// 少依赖"的取态一致），只取需要的 controlURL 与外网地址。
pub mod upnp {
    use std::net::Ipv4Addr;

    pub const ST_IGD: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";

    /// SSDP M-SEARCH 请求（组播到 239.255.255.250:1900）。
    pub fn msearch(st: &str) -> String {
        format!(
            "M-SEARCH * HTTP/1.1\r\n\
             HOST: 239.255.255.250:1900\r\n\
             MAN: \"ssdp:discover\"\r\n\
             MX: 2\r\n\
             ST: {st}\r\n\r\n"
        )
    }

    /// SSDP 应答里的 LOCATION 头。
    pub fn parse_location(response: &str) -> Option<String> {
        response
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("location")
                    .then(|| value.trim().to_string())
            })
            .filter(|url| url.starts_with("http"))
    }

    /// 设备描述 XML → 第一个 WANIPConnection / WANPPPConnection 的 controlURL
    /// 与 serviceType。base 是描述文档的 URL（相对 controlURL 按它解析）。
    pub fn parse_igd_service(desc_xml: &str, base_url: &str) -> Option<(String, String)> {
        for service_type in [
            "urn:schemas-upnp-org:service:WANIPConnection:2",
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANPPPConnection:1",
        ] {
            // 找到 serviceType 出现位置，向后截一段（service 定义块很短），
            // 在里面找 controlURL 标签。
            if let Some(offset) = desc_xml.find(service_type) {
                let window = &desc_xml[offset..(offset + 2000).min(desc_xml.len())];
                if let Some(url) = tag_text(window, "controlURL") {
                    return Some((resolve_url(base_url, &url)?, service_type.to_string()));
                }
            }
        }
        None
    }

    /// 相对 URL 按 base 解析成绝对（只处理 path 与 absolute 两种形态）。
    fn resolve_url(base: &str, url: &str) -> Option<String> {
        if url.starts_with("http://") || url.starts_with("https://") {
            return Some(url.to_string());
        }
        let (scheme, rest) = base.split_once("://")?;
        let (host, path) = rest.split_once('/')?;
        let base_dir = match path.rfind('/') {
            Some(index) => &path[..index],
            None => "",
        };
        let path = url.trim_start_matches('/');
        Some(format!("{scheme}://{host}{base_dir}/{path}"))
    }

    /// XML 里第一个 `<tag>text</tag>` 的 text（起始标签可能带属性）。
    pub fn tag_text(xml: &str, tag: &str) -> Option<String> {
        let open = format!("<{tag}");
        let close = format!("</{tag}>");
        let mut cursor = 0;
        while let Some(found) = xml[cursor..].find(&open) {
            let start = cursor + found;
            let Some(gt) = xml[start..].find('>') else {
                break;
            };
            // `<tag/>` 自闭合没有文本。
            if xml[start..start + gt].ends_with('/') {
                cursor = start + gt + 1;
                continue;
            }
            let content_start = start + gt + 1;
            let Some(end) = xml[content_start..].find(&close) else {
                break;
            };
            return Some(xml[content_start..content_start + end].trim().to_string());
        }
        None
    }

    /// `AddPortMapping` 的 SOAP 请求体（serviceType 用设备描述里发现的那个）。
    pub fn soap_add_mapping(
        service_type: &str,
        internal_ip: Ipv4Addr,
        external_port: u16,
        internal_port: u16,
        lease_secs: u32,
    ) -> String {
        soap_envelope(
            service_type,
            "AddPortMapping",
            &format!(
                "<NewRemoteHost></NewRemoteHost>\
                 <NewExternalPort>{external_port}</NewExternalPort>\
                 <NewProtocol>UDP</NewProtocol>\
                 <NewInternalPort>{internal_port}</NewInternalPort>\
                 <NewInternalClient>{internal_ip}</NewInternalClient>\
                 <NewEnabled>1</NewEnabled>\
                 <NewPortMappingDescription>HzNet hzd</NewPortMappingDescription>\
                 <NewLeaseDuration>{lease_secs}</NewLeaseDuration>"
            ),
        )
    }

    /// `DeletePortMapping` 的 SOAP 请求体。
    pub fn soap_delete_mapping(service_type: &str, external_port: u16) -> String {
        soap_envelope(
            service_type,
            "DeletePortMapping",
            &format!(
                "<NewRemoteHost></NewRemoteHost>\
                 <NewExternalPort>{external_port}</NewExternalPort>\
                 <NewProtocol>UDP</NewProtocol>"
            ),
        )
    }

    /// `GetExternalIPAddress` 的 SOAP 请求体。
    pub fn soap_get_external_ip(service_type: &str) -> String {
        soap_envelope(service_type, "GetExternalIPAddress", "")
    }

    /// SOAP 应答里的 `NewExternalIPAddress`。
    pub fn parse_external_ip(soap_response: &str) -> Option<Ipv4Addr> {
        tag_text(soap_response, "NewExternalIPAddress")?
            .parse()
            .ok()
    }

    /// SOAP 应答是否携带 UPnPError（fault）。
    pub fn is_fault(soap_response: &str) -> bool {
        soap_response.contains("UPnPError") || soap_response.contains("Fault>")
    }

    fn soap_envelope(service_type: &str, action: &str, arguments: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?>\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
             <s:Body><u:{action} xmlns:u=\"{service_type}\">\
             {arguments}\
             </u:{action}></s:Body></s:Envelope>"
        )
    }
}

// ---------------------------------------------------------------------------
// 网络交互
// ---------------------------------------------------------------------------

/// 依次尝试 PCP → NAT-PMP → UPnP，为 `wg_port` 申请 UDP 映射。
/// gateway 是默认网关；bind_egress 要求请求经物理出口网卡（FR-7），
/// 网关为回环（测试桩）时自动跳过绑定。所有协议都无响应返回 None
/// （netcheck 显示「不可用」）。
pub async fn request_mapping(
    gateway: Ipv4Addr,
    wg_port: u16,
    bind_egress: bool,
) -> anyhow::Result<Option<MappingOutcome>> {
    request_mapping_at(
        SocketAddr::new(std::net::IpAddr::V4(gateway), GATEWAY_PORT),
        wg_port,
        None,
        bind_egress,
    )
    .await
}

/// 同 [`request_mapping`]，但网关端点可指定（进程内测试桩用临时端口）。
/// renew 为 Some 时按既有租约续租：PCP 复用 nonce、三种协议都沿用旧外
/// 端口，避免候选地址漂移；None 表示首次申请（外端口由网关分配）。
pub async fn request_mapping_at(
    endpoint: SocketAddr,
    wg_port: u16,
    renew: Option<&PortMapLease>,
    bind_egress: bool,
) -> anyhow::Result<Option<MappingOutcome>> {
    let gateway = match endpoint.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => bail!("端口映射网关必须是 IPv4：{endpoint}"),
    };
    let bind_egress = bind_egress && !gateway.is_loopback();
    if let Some(outcome) = try_pcp(endpoint, wg_port, renew, bind_egress).await? {
        return Ok(Some(outcome));
    }
    if let Some(outcome) = try_natpmp(endpoint, wg_port, renew, bind_egress).await? {
        return Ok(Some(outcome));
    }
    if let Some(outcome) = try_upnp(gateway, wg_port, renew, bind_egress).await? {
        return Ok(Some(outcome));
    }
    Ok(None)
}

/// 尽力删除映射。PCP/NAT-PMP 发 lifetime=0 的删除报文（不等应答）；
/// UPnP 发 DeletePortMapping SOAP。失败只记日志。
pub async fn delete_mapping(lease: &PortMapLease, bind_egress: bool) {
    let bind_egress = bind_egress && !lease.gateway.ip().is_loopback();
    let result = match lease.protocol {
        PortMapProtocol::Pcp => pcp_delete(lease, bind_egress).await,
        PortMapProtocol::NatPmp => natpmp_delete(lease, bind_egress).await,
        PortMapProtocol::Upnp => upnp_delete(lease).await,
    };
    if let Err(error) = result {
        tracing::debug!(%error, protocol = lease.protocol.as_str(), "portmap delete failed (best effort)");
    }
}

/// 同步构造 PCP/NAT-PMP 的删除报文（hzd 退出路径的 Drop 里没有可用的
/// 异步运行时；UPnP 依赖租期自过期）。返回 (网关, 报文)。
pub fn delete_datagram(lease: &PortMapLease) -> Option<(SocketAddr, Vec<u8>)> {
    match lease.protocol {
        PortMapProtocol::NatPmp => Some((
            lease.gateway,
            natpmp::map_udp_request(lease.internal_port, lease.external.port(), 0).to_vec(),
        )),
        PortMapProtocol::Pcp => Some((
            lease.gateway,
            pcp::map_request(
                lease.pcp_nonce,
                lease.internal_port,
                lease.external.port(),
                0,
            ),
        )),
        PortMapProtocol::Upnp => None,
    }
}

async fn try_pcp(
    gateway: SocketAddr,
    wg_port: u16,
    renew: Option<&PortMapLease>,
    bind_egress: bool,
) -> anyhow::Result<Option<MappingOutcome>> {
    // 首次申请随机 nonce（网关分配外端口）；续租复用旧 nonce + 旧外端口，
    // 网关才会延续同一映射而不是另配一个。
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce = renew.map(|lease| lease.pcp_nonce).unwrap_or(nonce);
    let suggested = renew.map(|lease| lease.external.port()).unwrap_or(0);
    let request = pcp::map_request(nonce, wg_port, suggested, 3600);
    let sock = udp_socket(gateway, bind_egress).await?;
    let Some(response) = roundtrip(&sock, gateway, &request).await? else {
        return Ok(None);
    };
    let Some(parsed) = pcp::parse_map_response(&response) else {
        return Ok(None);
    };
    if parsed.result != pcp::RESULT_SUCCESS {
        tracing::debug!(result = parsed.result, "pcp map rejected");
        return Ok(None);
    }
    let v4 = match parsed.external.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    };
    Ok(Some(outcome_for(
        PortMapProtocol::Pcp,
        gateway,
        parsed.internal_port,
        v4,
        parsed.external.port(),
        parsed.lifetime_secs,
        None,
        nonce,
    )))
}

async fn try_natpmp(
    gateway: SocketAddr,
    wg_port: u16,
    renew: Option<&PortMapLease>,
    bind_egress: bool,
) -> anyhow::Result<Option<MappingOutcome>> {
    // 先查外网地址（顺带确认网关支持 NAT-PMP），再申请映射。
    let sock = udp_socket(gateway, bind_egress).await?;
    let Some(response) = roundtrip(&sock, gateway, &natpmp::external_addr_request()).await? else {
        return Ok(None);
    };
    let Some(external) = natpmp::parse_external_addr_response(&response) else {
        return Ok(None);
    };
    if external.result != natpmp::RESULT_SUCCESS {
        tracing::debug!(result = external.result, "nat-pmp external addr rejected");
        return Ok(None);
    }
    // 建议外端口：续租沿用旧端口，首次申请交给网关分配（0）。
    let suggested = renew.map(|lease| lease.external.port()).unwrap_or(0);
    let request = natpmp::map_udp_request(wg_port, suggested, 3600);
    let Some(response) = roundtrip(&sock, gateway, &request).await? else {
        return Ok(None);
    };
    let Some(mapped) = natpmp::parse_map_response(&response) else {
        return Ok(None);
    };
    if mapped.result != natpmp::RESULT_SUCCESS {
        tracing::debug!(result = mapped.result, "nat-pmp map rejected");
        return Ok(None);
    }
    Ok(Some(outcome_for(
        PortMapProtocol::NatPmp,
        gateway,
        mapped.internal_port,
        external.external,
        mapped.external_port,
        mapped.lifetime_secs,
        None,
        [0u8; 12],
    )))
}

async fn try_upnp(
    gateway: Ipv4Addr,
    wg_port: u16,
    renew: Option<&PortMapLease>,
    bind_egress: bool,
) -> anyhow::Result<Option<MappingOutcome>> {
    // SSDP 发现 IGD（经物理出口网卡的组播）。
    let sock = match udp_socket(SSDP_MULTICAST, bind_egress).await {
        Ok(sock) => sock,
        Err(error) => {
            tracing::debug!(%error, "ssdp socket failed");
            return Ok(None);
        }
    };
    sock.send_to(upnp::msearch(upnp::ST_IGD).as_bytes(), SSDP_MULTICAST)
        .await
        .context("ssdp m-search send failed")?;
    let mut buf = vec![0u8; 4096];
    let mut location = None;
    if let Ok(Ok((len, _))) = tokio::time::timeout(RESPONSE_TIMEOUT, sock.recv_from(&mut buf)).await
    {
        location = upnp::parse_location(&String::from_utf8_lossy(&buf[..len]));
    }
    let Some(location) = location else {
        return Ok(None);
    };
    // 设备描述：拿 controlURL 与 serviceType。
    let (status, body) = http_get(&location).await?;
    if !status.is_success() {
        tracing::debug!(%status, %location, "upnp description fetch failed");
        return Ok(None);
    }
    let Some((control_url, service_type)) = upnp::parse_igd_service(&body, &location) else {
        return Ok(None);
    };
    // 内网地址：网关同网段的本机地址（出口网卡上选一个）。
    let Some(internal_ip) = internal_ip_for_gateway(gateway) else {
        return Ok(None);
    };
    // 申请映射：外端口优先与内部端口一致；续租沿用旧外端口。
    let external_port = renew.map(|lease| lease.external.port()).unwrap_or(wg_port);
    let soap_body = upnp::soap_add_mapping(
        &service_type,
        internal_ip,
        external_port,
        wg_port,
        UPNP_LEASE_SECS,
    );
    let (status, body) =
        http_soap(&control_url, &service_type, "AddPortMapping", &soap_body).await?;
    if !status.is_success() || upnp::is_fault(&body) {
        tracing::debug!(%status, fault = upnp::is_fault(&body), "upnp AddPortMapping failed");
        return Ok(None);
    }
    // 外网地址：GetExternalIPAddress。
    let (status, body) = http_soap(
        &control_url,
        &service_type,
        "GetExternalIPAddress",
        &upnp::soap_get_external_ip(&service_type),
    )
    .await?;
    let Some(external) = (status.is_success() && !upnp::is_fault(&body))
        .then(|| upnp::parse_external_ip(&body))
        .flatten()
    else {
        return Ok(None);
    };
    Ok(Some(outcome_for(
        PortMapProtocol::Upnp,
        SocketAddr::new(std::net::IpAddr::V4(gateway), GATEWAY_PORT),
        wg_port,
        external,
        external_port,
        UPNP_LEASE_SECS,
        Some((control_url, service_type)),
        [0u8; 12],
    )))
}

/// 按外网地址分类组装结局：公网 → Mapped；否则多重 NAT。
#[allow(clippy::too_many_arguments)]
fn outcome_for(
    protocol: PortMapProtocol,
    gateway: SocketAddr,
    internal_port: u16,
    external_ip: Ipv4Addr,
    external_port: u16,
    lifetime_secs: u32,
    upnp: Option<(String, String)>,
    pcp_nonce: [u8; 12],
) -> MappingOutcome {
    match classify_external(external_ip) {
        ExternalClass::Public => MappingOutcome::Mapped(PortMapLease {
            protocol,
            gateway,
            internal_port,
            external: SocketAddr::new(std::net::IpAddr::V4(external_ip), external_port),
            lifetime_secs,
            upnp,
            pcp_nonce,
        }),
        _ => MappingOutcome::MultiNat {
            protocol,
            external: external_ip,
        },
    }
}

async fn pcp_delete(lease: &PortMapLease, bind_egress: bool) -> anyhow::Result<()> {
    // 删除必须用申请时的 nonce（网关按 nonce 归属映射）。
    let request = pcp::map_request(
        lease.pcp_nonce,
        lease.internal_port,
        lease.external.port(),
        0,
    );
    let sock = udp_socket(lease.gateway, bind_egress).await?;
    sock.send_to(&request, lease.gateway).await?;
    Ok(())
}

async fn natpmp_delete(lease: &PortMapLease, bind_egress: bool) -> anyhow::Result<()> {
    let request = natpmp::map_udp_request(lease.internal_port, lease.external.port(), 0);
    let sock = udp_socket(lease.gateway, bind_egress).await?;
    sock.send_to(&request, lease.gateway).await?;
    Ok(())
}

async fn upnp_delete(lease: &PortMapLease) -> anyhow::Result<()> {
    let Some((control_url, service_type)) = &lease.upnp else {
        return Ok(());
    };
    let body = upnp::soap_delete_mapping(service_type, lease.external.port());
    let _ = http_soap(control_url, service_type, "DeletePortMapping", &body).await?;
    Ok(())
}

/// 绑定（可选出口网卡）的 UDP socket。
async fn udp_socket(peer: SocketAddr, bind_egress: bool) -> anyhow::Result<tokio::net::UdpSocket> {
    let sock = tokio::net::UdpSocket::bind(if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    if bind_egress {
        crate::netif::bind_to_physical_egress(&sock);
    }
    Ok(sock)
}

/// 发一条 UDP 并等一条应答（超时返回 Ok(None)）。
async fn roundtrip(
    sock: &tokio::net::UdpSocket,
    peer: SocketAddr,
    request: &[u8],
) -> anyhow::Result<Option<Vec<u8>>> {
    sock.send_to(request, peer)
        .await
        .with_context(|| format!("portmap request send to {peer} failed"))?;
    let mut buf = vec![0u8; 1500];
    match tokio::time::timeout(RESPONSE_TIMEOUT, sock.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => Ok(Some(buf[..len].to_vec())),
        Ok(Err(error)) => Err(anyhow::Error::from(error).context("portmap response recv failed")),
        Err(_) => Ok(None),
    }
}

/// 网关同网段的本机 IPv4（UPnP 的 NewInternalClient）。
fn internal_ip_for_gateway(gateway: Ipv4Addr) -> Option<Ipv4Addr> {
    let mask = match gateway.octets()[0] {
        10 => Ipv4Addr::new(255, 0, 0, 0),
        172 if (16..=31).contains(&gateway.octets()[1]) => Ipv4Addr::new(255, 240, 0, 0),
        192 if gateway.octets()[1] == 168 => Ipv4Addr::new(255, 255, 0, 0),
        _ => Ipv4Addr::new(255, 255, 255, 0),
    };
    crate::endpoint::lan_ipv4_candidates()
        .into_iter()
        .filter(|ip| (u32::from(*ip) & u32::from(mask)) == (u32::from(gateway) & u32::from(mask)))
        .min_by_key(|ip| u32::from(*ip))
}

// ---------------------------------------------------------------------------
// 极简 HTTP/1.1 客户端（UPnP 的描述文档与 SOAP control 都是明文 HTTP）
// ---------------------------------------------------------------------------

async fn http_get(url: &str) -> anyhow::Result<(http_status::Status, String)> {
    http_request(url, "GET", &[], None).await
}

async fn http_soap(
    url: &str,
    service_type: &str,
    action: &str,
    body: &str,
) -> anyhow::Result<(http_status::Status, String)> {
    http_request(
        url,
        "POST",
        &[
            ("Content-Type", "text/xml; charset=\"utf-8\""),
            ("SOAPAction", &format!("\"{service_type}#{action}\"")),
        ],
        Some(body),
    )
    .await
}

/// 不可依赖 reqwest（hz-core 无该依赖）的极简状态码类型。
pub mod http_status {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Status(pub u16);

    impl Status {
        pub fn is_success(self) -> bool {
            (200..300).contains(&self.0)
        }
    }

    impl std::fmt::Display for Status {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }
}

async fn http_request(
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> anyhow::Result<(http_status::Status, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("UPnP 只走明文 HTTP：{url}"))?;
    let (host_port, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{path}");
    let mut request = format!("{method} {path} HTTP/1.1\r\nHOST: {host_port}\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    let body_bytes = body.unwrap_or("").as_bytes();
    request.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    ));
    // 经物理出口网卡连接（FR-7；loopback 不绑——测试桩在回环上）。
    let addrs: Vec<SocketAddr> = host_port
        .parse()
        .map(|addr| vec![addr])
        .or_else(|_| {
            std::net::ToSocketAddrs::to_socket_addrs(&(host_port, 80)).map(|addrs| addrs.collect())
        })
        .with_context(|| format!("解析 UPnP 控制端点 {host_port} 失败"))?;
    let mut connected = None;
    let mut last_error = anyhow::anyhow!("无可用地址：{host_port}");
    for addr in addrs {
        match crate::coord_client::connect_bound(addr).await {
            Ok(bound) => {
                connected = Some(bound);
                break;
            }
            Err(error) => last_error = anyhow::Error::new(error),
        }
    }
    let mut stream = connected
        .ok_or_else(|| last_error.context(format!("连接 UPnP 控制端点 {host_port} 失败")))?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body_bytes).await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let text = String::from_utf8_lossy(&raw);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    Ok((http_status::Status(status), body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_address_classification_table() {
        // 公网。
        assert_eq!(
            classify_external("203.0.113.9".parse().unwrap()),
            ExternalClass::Public
        );
        assert_eq!(
            classify_external("1.1.1.1".parse().unwrap()),
            ExternalClass::Public
        );
        // 私网（RFC1918 / 回环 / 链路本地 / 未指定）。
        assert_eq!(
            classify_external("192.168.115.116".parse().unwrap()),
            ExternalClass::Private
        );
        assert_eq!(
            classify_external("10.0.0.1".parse().unwrap()),
            ExternalClass::Private
        );
        assert_eq!(
            classify_external("172.16.0.1".parse().unwrap()),
            ExternalClass::Private
        );
        assert_eq!(
            classify_external("172.31.255.255".parse().unwrap()),
            ExternalClass::Private
        );
        assert_eq!(
            classify_external("127.0.0.1".parse().unwrap()),
            ExternalClass::Private
        );
        assert_eq!(
            classify_external("169.254.1.1".parse().unwrap()),
            ExternalClass::Private
        );
        // CGNAT 100.64/10。
        assert_eq!(
            classify_external("100.64.0.1".parse().unwrap()),
            ExternalClass::Cgnat
        );
        assert_eq!(
            classify_external("100.127.255.255".parse().unwrap()),
            ExternalClass::Cgnat
        );
        assert_eq!(
            classify_external("100.63.255.255".parse().unwrap()),
            ExternalClass::Public
        );
        // 198.18.0.0/15。
        assert_eq!(
            classify_external("198.18.0.1".parse().unwrap()),
            ExternalClass::Benchmark
        );
        assert_eq!(
            classify_external("198.19.255.255".parse().unwrap()),
            ExternalClass::Benchmark
        );
        assert_eq!(
            classify_external("198.17.0.1".parse().unwrap()),
            ExternalClass::Public
        );
        assert_eq!(
            classify_external("198.20.0.1".parse().unwrap()),
            ExternalClass::Public
        );
    }

    #[test]
    fn natpmp_requests_and_responses_round_trip() {
        let external = natpmp::external_addr_request();
        assert_eq!(external, [0, 0]);
        // 外网地址应答（私网地址 → 多重 NAT 场景的实测形态）。
        let mut response = vec![0u8, 0x80, 0, 0];
        response.extend_from_slice(&1_234u32.to_be_bytes());
        response.extend_from_slice(&[192, 168, 115, 116]);
        let parsed = natpmp::parse_external_addr_response(&response).unwrap();
        assert_eq!(parsed.result, natpmp::RESULT_SUCCESS);
        assert_eq!(
            parsed.external,
            "192.168.115.116".parse::<Ipv4Addr>().unwrap()
        );

        // 映射请求：opcode 2、内端口 51820、建议外端口 0、租期 3600。
        let request = natpmp::map_udp_request(51820, 0, 3600);
        assert_eq!(request[1], 2);
        assert_eq!(u16::from_be_bytes([request[4], request[5]]), 51820);
        assert_eq!(
            u32::from_be_bytes([request[8], request[9], request[10], request[11]]),
            3600
        );
        // 删除请求：租期 0。
        let delete = natpmp::map_udp_request(51820, 52001, 0);
        assert_eq!(
            u32::from_be_bytes([delete[8], delete[9], delete[10], delete[11]]),
            0
        );

        // 映射应答。
        let mut response = vec![0u8, 0x82, 0, 0];
        response.extend_from_slice(&7u32.to_be_bytes());
        response.extend_from_slice(&51820u16.to_be_bytes());
        response.extend_from_slice(&52001u16.to_be_bytes());
        response.extend_from_slice(&7200u32.to_be_bytes());
        let parsed = natpmp::parse_map_response(&response).unwrap();
        assert_eq!(parsed.result, natpmp::RESULT_SUCCESS);
        assert_eq!(parsed.internal_port, 51820);
        assert_eq!(parsed.external_port, 52001);
        assert_eq!(parsed.lifetime_secs, 7200);
        // 残缺 / 错 opcode 的应答拒绝。
        assert!(natpmp::parse_map_response(&response[..12]).is_none());
        let mut wrong = response.clone();
        wrong[1] = 0x81;
        assert!(natpmp::parse_map_response(&wrong).is_none());
    }

    #[test]
    fn pcp_map_request_and_response_round_trip() {
        let nonce = [7u8; 12];
        let request = pcp::map_request(nonce, 51820, 0, 3600);
        assert_eq!(request.len(), 60);
        assert_eq!(request[0], pcp::VERSION);
        assert_eq!(request[1], pcp::OPCODE_MAP);
        assert_eq!(request[4..8], 3600u32.to_be_bytes());
        assert_eq!(request[24..36], nonce);
        assert_eq!(request[36], pcp::PROTOCOL_UDP);
        assert_eq!(u16::from_be_bytes([request[40], request[41]]), 51820);

        // 应答：公共头（ver, opcode|0x80, reserved, result, lifetime, epoch,
        // reserved 12B）= 24 字节；MAP 载荷 nonce(12) proto(1) rsv(3)
        // internal(2) external addr(16) external port(2) = 36 字节。
        let mut response = vec![pcp::VERSION, pcp::OPCODE_MAP | 0x80, 0, 0];
        response.extend_from_slice(&7200u32.to_be_bytes());
        response.extend_from_slice(&9u32.to_be_bytes());
        response.extend_from_slice(&[0u8; 12]);
        response.extend_from_slice(&nonce);
        response.push(pcp::PROTOCOL_UDP);
        response.extend_from_slice(&[0u8; 3]);
        response.extend_from_slice(&51820u16.to_be_bytes());
        let mut mapped = [0u8; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12..16].copy_from_slice(&[198, 51, 100, 7]);
        response.extend_from_slice(&mapped);
        response.extend_from_slice(&52001u16.to_be_bytes());
        assert_eq!(response.len(), 60);

        let parsed = pcp::parse_map_response(&response).unwrap();
        assert_eq!(parsed.result, pcp::RESULT_SUCCESS);
        assert_eq!(parsed.lifetime_secs, 7200);
        assert_eq!(parsed.internal_port, 51820);
        assert_eq!(parsed.external, "198.51.100.7:52001".parse().unwrap());
    }

    #[test]
    fn upnp_ssdp_and_soap_parsing() {
        let search = upnp::msearch(upnp::ST_IGD);
        assert!(search.contains("M-SEARCH * HTTP/1.1"));
        assert!(search.contains("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1"));

        let response = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.31.1:5000/rootDesc.xml\r\nSERVER: MiniUPnPd\r\n\r\n";
        assert_eq!(
            upnp::parse_location(response).as_deref(),
            Some("http://192.168.31.1:5000/rootDesc.xml")
        );
        assert!(upnp::parse_location("HTTP/1.1 200 OK\r\n\r\n").is_none());

        let desc = "<device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service></serviceList></device>";
        let (url, service) =
            upnp::parse_igd_service(desc, "http://192.168.31.1:5000/rootDesc.xml").unwrap();
        assert_eq!(url, "http://192.168.31.1:5000/ctl/IPConn");
        assert!(service.contains("WANIPConnection"));
        // 相对 controlURL 按 base 解析（base 的主机换人时跟着换）。
        let (url, _) = upnp::parse_igd_service(desc, "http://10.0.0.138:49152/d.xml").unwrap();
        assert_eq!(url, "http://10.0.0.138:49152/ctl/IPConn");

        let soap = upnp::soap_add_mapping(
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "192.168.31.63".parse().unwrap(),
            51820,
            51820,
            3600,
        );
        assert!(soap.contains("<NewExternalPort>51820</NewExternalPort>"));
        assert!(soap.contains("<NewProtocol>UDP</NewProtocol>"));
        assert!(soap.contains("<NewInternalClient>192.168.31.63</NewInternalClient>"));
        // 命名空间用发现的 serviceType，而不是硬编码。
        assert!(soap.contains("xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\""));

        let external = "<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>1.2.3.4</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>";
        assert_eq!(
            upnp::parse_external_ip(external),
            Some("1.2.3.4".parse().unwrap())
        );
        assert!(!upnp::is_fault(external));
        assert!(upnp::is_fault(
            "<s:Fault><detail><UPnPError/></detail></s:Fault>"
        ));
    }

    /// 进程内 NAT-PMP 应答器：公网外网地址 → Mapped（PortMap 候选）；
    /// 私网外网地址 → MultiNat（不上报候选）。
    #[tokio::test]
    async fn natpmp_gateway_public_external_maps_and_private_flags_multi_nat() {
        for (external_ip, expect_public) in [("203.0.113.9", true), ("192.168.115.116", false)] {
            let endpoint = spawn_natpmp_stub(external_ip.parse().unwrap()).await;
            let outcome = request_mapping_at(endpoint, 51820, None, true)
                .await
                .unwrap()
                .expect("NAT-PMP 桩应答了");
            if expect_public {
                let MappingOutcome::Mapped(lease) = outcome else {
                    panic!("公网外网地址应为 Mapped：{outcome:?}");
                };
                assert_eq!(lease.protocol, PortMapProtocol::NatPmp);
                assert_eq!(lease.internal_port, 51820);
                assert_eq!(lease.external.ip().to_string(), external_ip);
                assert_eq!(lease.external.port(), 52001);
                assert!(lease.lifetime_secs > 0);
            } else {
                let MappingOutcome::MultiNat { protocol, external } = outcome else {
                    panic!("私网外网地址应判多重 NAT：{outcome:?}");
                };
                assert_eq!(protocol, PortMapProtocol::NatPmp);
                assert_eq!(external.to_string(), external_ip);
            }
        }
    }

    /// 删除映射：桩收到 lifetime=0 的删除报文。
    #[tokio::test]
    async fn natpmp_delete_sends_zero_lifetime() {
        let captured: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = sock.local_addr().unwrap();
        let server = {
            let sock = std::sync::Arc::new(sock);
            let captured = captured.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1500];
                loop {
                    let Ok((_len, from)) = sock.recv_from(&mut buf).await else {
                        return;
                    };
                    captured.lock().unwrap().push(buf[.._len].to_vec());
                    if buf[1] == 0 {
                        // 外网地址查询。
                        let mut response = vec![0, 0x80, 0, 0];
                        response.extend_from_slice(&0u32.to_be_bytes());
                        response.extend_from_slice(&[203, 0, 113, 9]);
                        let _ = sock.send_to(&response, from).await;
                    } else if buf[1] == 2 {
                        let mut response = vec![0, 0x82, 0, 0];
                        response.extend_from_slice(&0u32.to_be_bytes());
                        response.extend_from_slice(&51820u16.to_be_bytes());
                        response.extend_from_slice(&52001u16.to_be_bytes());
                        response.extend_from_slice(&7200u32.to_be_bytes());
                        let _ = sock.send_to(&response, from).await;
                    }
                }
            })
        };
        let outcome = request_mapping_at(endpoint, 51820, None, true)
            .await
            .unwrap()
            .unwrap();
        let MappingOutcome::Mapped(lease) = outcome else {
            panic!("stub 应回 Mapped：{outcome:?}");
        };
        delete_mapping(&lease, true).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await; // 让删除报文先进桩
        server.abort();
        let requests = captured.lock().unwrap().clone();
        let delete = requests
            .iter()
            .rev()
            .find(|message| message.len() == 12 && message[1] == 2)
            .expect("应发出 NAT-PMP 删除报文");
        assert_eq!(
            u32::from_be_bytes([delete[8], delete[9], delete[10], delete[11]]),
            0
        );
    }

    /// 续租端口稳定（#77 评审项）：第二次申请带 renew 时，建议外端口是旧
    /// 外端口而不是 0，桩据此回同一端口——候选地址不漂移。
    #[tokio::test]
    async fn renew_reuses_the_previous_external_port() {
        let requests: std::sync::Arc<std::sync::Mutex<Vec<u16>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = sock.local_addr().unwrap();
        let server = {
            let sock = std::sync::Arc::new(sock);
            let requests = requests.clone();
            tokio::spawn(async move {
                let sock = sock.clone();
                let mut buf = [0u8; 1500];
                loop {
                    let Ok((_, from)) = sock.recv_from(&mut buf).await else {
                        return;
                    };
                    let reply = if buf[1] == 0 {
                        let mut response = vec![0, 0x80, 0, 0];
                        response.extend_from_slice(&0u32.to_be_bytes());
                        response.extend_from_slice(&[203, 0, 113, 9]);
                        response
                    } else if buf[1] == 2 {
                        // 回显建议的外端口（0 → 分配 52001），记录每次的建议值。
                        let suggested = u16::from_be_bytes([buf[6], buf[7]]);
                        requests.lock().unwrap().push(suggested);
                        let granted = if suggested == 0 { 52001 } else { suggested };
                        let mut response = vec![0, 0x82, 0, 0];
                        response.extend_from_slice(&0u32.to_be_bytes());
                        response.extend_from_slice(&51820u16.to_be_bytes());
                        response.extend_from_slice(&granted.to_be_bytes());
                        response.extend_from_slice(&7200u32.to_be_bytes());
                        response
                    } else {
                        continue;
                    };
                    let _ = sock.send_to(&reply, from).await;
                }
            })
        };
        let first = request_mapping_at(endpoint, 51820, None, true)
            .await
            .unwrap()
            .unwrap();
        let MappingOutcome::Mapped(lease) = first else {
            panic!("首次申请应成功：{first:?}")
        };
        let renewed = request_mapping_at(endpoint, 51820, Some(&lease), true)
            .await
            .unwrap()
            .unwrap();
        let MappingOutcome::Mapped(renewed) = renewed else {
            panic!("续租应成功：{renewed:?}")
        };
        server.abort();
        assert_eq!(renewed.external, lease.external, "续租保住同一外网地址");
        let suggestions = requests.lock().unwrap().clone();
        assert_eq!(
            suggestions,
            vec![0, lease.external.port()],
            "续租的建议外端口沿用旧值"
        );
    }

    async fn spawn_natpmp_stub(external_ip: Ipv4Addr) -> SocketAddr {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let sock = std::sync::Arc::new(sock);
            let mut buf = [0u8; 1500];
            loop {
                let Ok((_len, from)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let reply = if buf[1] == 0 {
                    // 外网地址查询。
                    let mut response = vec![0, 0x80, 0, 0];
                    response.extend_from_slice(&0u32.to_be_bytes());
                    response.extend_from_slice(&external_ip.octets());
                    response
                } else if buf[1] == 2 {
                    // UDP 映射申请 / 删除（lifetime 0 的删除也按成功应答）。
                    let lifetime = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]).max(7200);
                    let mut response = vec![0, 0x82, 0, 0];
                    response.extend_from_slice(&0u32.to_be_bytes());
                    response.extend_from_slice(&51820u16.to_be_bytes());
                    response.extend_from_slice(&52001u16.to_be_bytes());
                    response.extend_from_slice(&lifetime.to_be_bytes());
                    response
                } else {
                    continue;
                };
                let _ = sock.send_to(&reply, from).await;
            }
        });
        endpoint
    }
}
