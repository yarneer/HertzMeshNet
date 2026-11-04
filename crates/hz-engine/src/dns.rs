//! 本地 DNS 应答器（FR-5 / A2，平台无关部分）：在保留地址 100.96.0.53:53
//! 上应答 `<NodeName>.<suffix>` 的 A/AAAA 查询，数据来自 Network Map 缓存的
//! 实时快照。线格式按 RFC 1035 手写编码（只做应答 A/AAAA +
//! REFUSED/NXDOMAIN，不递归），垃圾报文回 FORMERR。
//! 桌面的系统接入（systemd-resolved 分域、/etc/resolver、resolv.conf 退路）
//! 留在 hzd 的 Platform 实现；Android 由 VpnService 声明 DNS 服务器。
//!
//! #98 转发模式（规格 §5.2，仅 Android）：VpnService 一旦声明 DNS 服务器，
//! 走 VPN 网络的 App 的全部查询都发到本应答器——后缀外查询经
//! `Platform::protect` 的 socket 原样转发给 `Platform::system_dns()` 的上游
//! （UDP 优先、TC 截断改 TCP、依次尝试、全失败 SERVFAIL）；桌面不开转发
//! 模式，后缀外照旧 REFUSED（分域接管）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use hz_core::dns::DNS_PORT;
use hz_core::map::{MapNode, NetworkMapCache};

use crate::platform::Platform;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const FLAG_RD: u16 = 0x0100;
const RCODE_FORMERR: u16 = 1;
const RCODE_NXDOMAIN: u16 = 3;
const RCODE_REFUSED: u16 = 5;
const ANSWER_TTL_SECS: u32 = 60;

/// 解析出的查询问题区；label 保留原始大小写用于回显。
struct Question {
    id: u16,
    flags: u16,
    labels: Vec<Vec<u8>>,
    qtype: u16,
    qclass: u16,
}

/// 一条查询的应答决策：命中出地址，后缀内未知名 NXDOMAIN，
/// 后缀外（本服务不递归）REFUSED，命中但无该类型记录 NODATA。
enum Decision {
    Answer { rtype: u16, rdata: Vec<u8> },
    NxDomain,
    NoData,
    Refused,
}

fn decide(question: &Question, nodes: &[MapNode], suffix: &str) -> Decision {
    let dotted = dotted_lower(&question.labels);
    let Some(node_part) = dotted.strip_suffix(&format!(".{suffix}")) else {
        return Decision::Refused;
    };
    // 只应答 `<单个 NodeName>.<suffix>`；带下级标签的名字不归任何 Node。
    if node_part.is_empty() || node_part.contains('.') {
        return Decision::NxDomain;
    }
    let Some(node) = nodes
        .iter()
        .find(|node| node.name.to_lowercase() == node_part)
    else {
        return Decision::NxDomain;
    };
    let answer = match question.qtype {
        TYPE_A => node
            .ipv4
            .parse::<Ipv4Addr>()
            .ok()
            .map(|addr| (TYPE_A, addr.octets().to_vec())),
        TYPE_AAAA => node
            .ipv6
            .parse::<Ipv6Addr>()
            .ok()
            .map(|addr| (TYPE_AAAA, addr.octets().to_vec())),
        _ => None,
    };
    match answer {
        Some((rtype, rdata)) => Decision::Answer { rtype, rdata },
        None => Decision::NoData,
    }
}

fn dotted_lower(labels: &[Vec<u8>]) -> String {
    labels
        .iter()
        .map(|label| String::from_utf8_lossy(label).to_lowercase())
        .collect::<Vec<_>>()
        .join(".")
}

/// 查询报文 → 应答报文。解析失败回仅含 id 的 FORMERR 头。
fn build_response(query: &[u8], nodes: &[MapNode], suffix: &str) -> Vec<u8> {
    let question = match parse_query(query) {
        Ok(question) => question,
        Err(error_id) => return formerr(error_id),
    };
    let decision = decide(&question, nodes, suffix);
    let rcode = match &decision {
        Decision::Answer { .. } | Decision::NoData => 0,
        Decision::NxDomain => RCODE_NXDOMAIN,
        Decision::Refused => RCODE_REFUSED,
    };
    let mut out = Vec::with_capacity(query.len() + 28);
    out.extend_from_slice(&question.id.to_be_bytes());
    out.extend_from_slice(&(FLAG_QR | FLAG_AA | (question.flags & FLAG_RD) | rcode).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(matches!(decision, Decision::Answer { .. }) as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    push_name(&mut out, &question.labels);
    out.extend_from_slice(&question.qtype.to_be_bytes());
    out.extend_from_slice(&question.qclass.to_be_bytes());
    if let Decision::Answer { rtype, rdata } = &decision {
        push_name(&mut out, &question.labels);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ANSWER_TTL_SECS.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }
    out
}

fn push_name(out: &mut Vec<u8>, labels: &[Vec<u8>]) {
    for label in labels {
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
}

fn formerr(id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(FLAG_QR | RCODE_FORMERR).to_be_bytes());
    out.extend_from_slice(&[0; 8]);
    out
}

/// 只取第一个问题区（qdcount != 1 视为坏报文）；后续 additional/EDNS 一律忽略。
fn parse_query(msg: &[u8]) -> Result<Question, u16> {
    let id = msg
        .get(..2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .unwrap_or(0);
    if msg.len() < 12 || u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return Err(id);
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let (labels, cursor) = read_name(msg, 12).ok_or(id)?;
    if cursor + 4 > msg.len() {
        return Err(id);
    }
    let qtype = u16::from_be_bytes([msg[cursor], msg[cursor + 1]]);
    let qclass = u16::from_be_bytes([msg[cursor + 2], msg[cursor + 3]]);
    Ok(Question {
        id,
        flags,
        labels,
        qtype,
        qclass,
    })
}

/// 读一个名字（支持压缩指针）；返回 label 列表与名字结束后的偏移。
fn read_name(msg: &[u8], start: usize) -> Option<(Vec<Vec<u8>>, usize)> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut after_name = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)?;
        if len & 0xC0 == 0xC0 {
            after_name = after_name.or(Some(pos + 2));
            jumps += 1;
            if jumps > 32 {
                return None;
            }
            pos = (((len & 0x3F) as usize) << 8) | *msg.get(pos + 1)? as usize;
            continue;
        }
        if len & 0xC0 != 0 || labels.len() > 128 {
            return None;
        }
        if len == 0 {
            return Some((labels, after_name.unwrap_or(pos + 1)));
        }
        let end = pos.checked_add(1 + len as usize)?;
        labels.push(msg[pos + 1..end].to_vec());
        pos = end;
    }
}

/// TCP DNS 报文带 2 字节长度前缀；返回 None 表示对端关闭。
async fn read_tcp_message(stream: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).await.ok()?;
    let len = u16::from_be_bytes(prefix) as usize;
    let mut message = vec![0u8; len];
    stream.read_exact(&mut message).await.ok()?;
    Some(message)
}

async fn write_tcp_message(
    stream: &mut tokio::net::TcpStream,
    message: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut framed = (message.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(message);
    stream.write_all(&framed).await
}

const RCODE_SERVFAIL: u16 = 2;

/// 单个上游转发的超时（#98：依次尝试各服务器，总预算受此约束）。
pub const FORWARD_TIMEOUT: Duration = Duration::from_secs(3);

/// 转发模式的上游配置：经 Platform 拿服务器列表（网络切换后自动跟上）
/// 并 protect 转发 socket（不进本 HzNet 的 TUN）。
#[derive(Clone)]
pub struct Forwarding {
    pub platform: Arc<dyn Platform>,
    pub timeout: Duration,
    /// 上游端口（生产恒为 53；测试用假上游的随机端口注入）。
    pub upstream_port: u16,
}

impl Forwarding {
    /// 生产构造：标准 DNS 端口。
    pub fn new(platform: Arc<dyn Platform>) -> Self {
        Self {
            platform,
            timeout: FORWARD_TIMEOUT,
            upstream_port: DNS_PORT,
        }
    }

    fn upstream(&self, server: IpAddr) -> SocketAddr {
        SocketAddr::new(server, self.upstream_port)
    }
}

/// 查询 id（报文头前两字节）；短报文取 0。
fn query_id_of(message: &[u8]) -> u16 {
    message
        .get(..2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .unwrap_or(0)
}

/// 应答的 TC（截断）位。
fn is_truncated(message: &[u8]) -> bool {
    message.get(2).is_some_and(|flags| flags & 0x02 != 0)
}

/// 仅含 id 的 SERVFAIL 头（#98：上游全部不可达时）。
fn servfail(id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(FLAG_QR | RCODE_SERVFAIL).to_be_bytes());
    out.extend_from_slice(&[0; 8]);
    out
}

/// 经 protect 的 UDP socket 向上游转发一次查询，等待 id 匹配的应答。
async fn forward_udp(
    server: IpAddr,
    query: &[u8],
    forward: &Forwarding,
) -> std::io::Result<Vec<u8>> {
    let bind_addr: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
    let _ = forward.platform.protect(socket.as_raw_fd());
    let upstream = forward.upstream(server);
    socket.send_to(query, upstream).await?;
    let qid = query_id_of(query);
    let mut buf = vec![0u8; 4096];
    loop {
        let (len, from) = tokio::time::timeout(forward.timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "上游转发超时"))??;
        if from == upstream && query_id_of(&buf[..len]) == qid {
            return Ok(buf[..len].to_vec());
        }
    }
}

/// 经 protect 的 TCP 连接向上游转发（UDP 应答 TC 截断时改走，RFC 1035 §4.2.2）。
async fn forward_tcp(
    server: IpAddr,
    query: &[u8],
    forward: &Forwarding,
) -> std::io::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let upstream = forward.upstream(server);
    let socket = socket2::Socket::new(
        if upstream.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    // protect 必须在 connect(2) 之前（Android VpnService.protect 的要求）。
    let _ = forward.platform.protect(socket.as_raw_fd());
    socket.set_nonblocking(true)?;
    match socket.connect(&socket2::SockAddr::from(upstream)) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(error) => return Err(error),
    }
    let mut stream = tokio::net::TcpStream::from_std(socket.into())?;
    stream.writable().await?;
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(query).await?;
    let mut prefix = [0u8; 2];
    tokio::time::timeout(forward.timeout, stream.read_exact(&mut prefix)).await??;
    let len = u16::from_be_bytes(prefix) as usize;
    let mut message = vec![0u8; len];
    tokio::time::timeout(forward.timeout, stream.read_exact(&mut message)).await??;
    Ok(message)
}

/// 依次尝试上游：UDP 优先，TC 截断改 TCP（TCP 也失败退回截断应答）；
/// 全部失败返回 None（调用方回 SERVFAIL）。服务器列表由调用方每轮现取
/// （`Platform::system_dns`，网络切换后自动用新列表）。
async fn resolve_via_upstream(
    servers: &[IpAddr],
    query: &[u8],
    forward: &Forwarding,
) -> Option<Vec<u8>> {
    for server in servers {
        if let Ok(answer) = forward_udp(*server, query, forward).await {
            if is_truncated(&answer) {
                if let Ok(full) = forward_tcp(*server, query, forward).await {
                    return Some(full);
                }
                return Some(answer);
            }
            return Some(answer);
        }
    }
    None
}

/// 一条查询的完整应答决策：后缀内本地应答；后缀外按转发模式转发
/// （未启用则 REFUSED，与桌面行为一致）。
async fn respond(
    query: &[u8],
    nodes: &[MapNode],
    suffix: &str,
    forward: Option<&Forwarding>,
) -> Vec<u8> {
    let question = match parse_query(query) {
        Ok(question) => question,
        Err(error_id) => return formerr(error_id),
    };
    if matches!(decide(&question, nodes, suffix), Decision::Refused) {
        if let Some(forward) = forward {
            let servers = forward.platform.system_dns();
            if servers.is_empty() {
                return servfail(question.id);
            }
            if let Some(answer) = resolve_via_upstream(&servers, query, forward).await {
                return answer;
            }
            return servfail(question.id);
        }
    }
    build_response(query, nodes, suffix)
}

/// 在指定地址起 UDP + TCP 应答循环（测试可用 127.0.0.1:0），返回实际绑定地址。
pub async fn spawn_responder(
    addr: SocketAddr,
    cache: Arc<NetworkMapCache>,
    suffix: String,
    forward: Option<Forwarding>,
) -> anyhow::Result<SocketAddr> {
    let udp = tokio::net::UdpSocket::bind(addr)
        .await
        .with_context(|| format!("bind udp {addr} 失败（辅助地址已挂到 hz0？）"))?;
    let bound = udp.local_addr()?;
    let tcp = tokio::net::TcpListener::bind(bound)
        .await
        .with_context(|| format!("bind tcp {bound} 失败"))?;
    let suffix = Arc::new(suffix);

    tokio::spawn({
        let cache = cache.clone();
        let suffix = suffix.clone();
        let forward = forward.clone();
        async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                let response =
                    respond(&buf[..len], &cache.snapshot(), &suffix, forward.as_ref()).await;
                let _ = udp.send_to(&response, peer).await;
            }
        }
    });

    tokio::spawn({
        let cache = cache.clone();
        let suffix = suffix.clone();
        async move {
            loop {
                let Ok((mut stream, _)) = tcp.accept().await else {
                    continue;
                };
                let cache = cache.clone();
                let suffix = suffix.clone();
                let forward = forward.clone();
                tokio::spawn(async move {
                    while let Some(query) = read_tcp_message(&mut stream).await {
                        let response =
                            respond(&query, &cache.snapshot(), &suffix, forward.as_ref()).await;
                        if write_tcp_message(&mut stream, &response).await.is_err() {
                            return;
                        }
                    }
                });
            }
        }
    });

    Ok(bound)
}

/// 进程级"只起一次"标记：应答器端口绑定后随进程存活，`up` 恢复不重复绑定。
static STARTED: AtomicBool = AtomicBool::new(false);

/// 引擎数据面拉起时的应答器入口（幂等）：在 `(dns_v4, 53)` 上起 UDP + TCP
/// 应答循环。绑定失败（无 root / 辅助地址未挂）由调用方记告警，控制面照常。
pub async fn ensure_responder(
    cache: Arc<NetworkMapCache>,
    dns_v4: Ipv4Addr,
    forward: Option<Forwarding>,
) -> anyhow::Result<()> {
    if STARTED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let suffix = hz_core::dns::dns_suffix();
    let addr = SocketAddr::from((dns_v4, DNS_PORT));
    match spawn_responder(addr, cache, suffix.clone(), forward).await {
        Ok(bound) => {
            tracing::info!(%bound, suffix = %suffix, "local dns responder started");
            Ok(())
        }
        Err(error) => {
            STARTED.store(false, Ordering::SeqCst);
            Err(error)
        }
    }
}

/// TUN 内 DNS 应答（Android）：`dns_v4` 不是本机地址、普通 App 也绑不了
/// 53 端口，`ensure_responder` 在 Android 上必然失败；系统发往 `dns_v4` 的
/// 查询以 IP 包的形式从 TUN 读出。引擎在读循环里认出这些包，用与 socket
/// 应答器相同的决策（`respond`）应答，再把回包写回 TUN。桌面上 `dns_v4`
/// 是 hz0 的本机辅助地址，这类包不会进 TUN。只处理 IPv4 UDP（VpnService
/// 只声明了 v4 DNS 服务器；系统解析器走 UDP）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunQuery {
    src: Ipv4Addr,
    sport: u16,
    dst: Ipv4Addr,
    payload: Vec<u8>,
}

const IPPROTO_UDP: u8 = 17;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

/// 认出发往 `dns_v4:53` 的 IPv4 UDP 查询包；其余包（含分片）返回 None。
pub fn parse_tun_query(packet: &[u8], dns_v4: Ipv4Addr) -> Option<TunQuery> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 || packet[9] != IPPROTO_UDP {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    let total = (u16::from_be_bytes([packet[2], packet[3]]) as usize).min(packet.len());
    if ihl < IPV4_HEADER_LEN || total < ihl + UDP_HEADER_LEN {
        return None;
    }
    // MF 位或片偏移非零：分片的 DNS 查询不在 TUN 内重组，交给原路径（丢弃）。
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
        return None;
    }
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let udp = &packet[ihl..total];
    if dst != dns_v4 || u16::from_be_bytes([udp[2], udp[3]]) != DNS_PORT {
        return None;
    }
    let udp_len = (u16::from_be_bytes([udp[4], udp[5]]) as usize).min(udp.len());
    if udp_len < UDP_HEADER_LEN {
        return None;
    }
    Some(TunQuery {
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        sport: u16::from_be_bytes([udp[0], udp[1]]),
        dst,
        payload: udp[UDP_HEADER_LEN..udp_len].to_vec(),
    })
}

/// RFC 1071 反码和（未取反）。
fn ones_complement_sum(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    sum
}

fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 把 DNS 应答封成从 `dns_v4:53` 发回查询方的 IPv4 UDP 包（带 IP 与 UDP 校验和）。
pub fn build_tun_reply(query: &TunQuery, answer: &[u8]) -> Vec<u8> {
    let udp_len = UDP_HEADER_LEN + answer.len();
    let total = IPV4_HEADER_LEN + udp_len;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&[0x45, 0]);
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0x40, 0, 64, IPPROTO_UDP, 0, 0]);
    out.extend_from_slice(&query.dst.octets());
    out.extend_from_slice(&query.src.octets());
    let ip_checksum = fold_checksum(ones_complement_sum(0, &out[..IPV4_HEADER_LEN]));
    out[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    out.extend_from_slice(&DNS_PORT.to_be_bytes());
    out.extend_from_slice(&query.sport.to_be_bytes());
    out.extend_from_slice(&(udp_len as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(answer);
    // 伪首部：源、目的、协议、UDP 长度。
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&query.dst.octets());
    pseudo.extend_from_slice(&query.src.octets());
    pseudo.extend_from_slice(&[0, IPPROTO_UDP]);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    let sum = ones_complement_sum(ones_complement_sum(0, &pseudo), &out[IPV4_HEADER_LEN..]);
    // UDP 校验和算出 0 时按 RFC 768 写全 1（0 表示"未计算"）。
    let udp_checksum = match fold_checksum(sum) {
        0 => 0xffff,
        value => value,
    };
    out[IPV4_HEADER_LEN + 6..IPV4_HEADER_LEN + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    out
}

/// 应答一条 TUN 内查询，返回要写回 TUN 的完整 IP 包。
pub async fn answer_tun_query(
    query: &TunQuery,
    nodes: &[MapNode],
    suffix: &str,
    forward: Option<&Forwarding>,
) -> Vec<u8> {
    let answer = respond(&query.payload, nodes, suffix, forward).await;
    build_tun_reply(query, &answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, ipv4: &str, ipv6: &str) -> MapNode {
        MapNode {
            node_id: format!("id-{name}"),
            name: name.to_string(),
            ipv4: ipv4.to_string(),
            ipv6: ipv6.to_string(),
            tags: vec![],
            owner_user: None,
            expires_at_unix: None,
            node_key_pub: vec![],
            endpoints: vec![],
            detailed_endpoints: vec![],
        }
    }

    fn fixture() -> Vec<MapNode> {
        vec![node("db-1", "100.96.0.7", "fd12:3456:789a::6460:7")]
    }

    fn wire_query(id: u16, flags: u16, labels: &[&[u8]], qtype: u16) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&id.to_be_bytes());
        query.extend_from_slice(&flags.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&[0; 6]);
        push_name(
            &mut query,
            &labels.iter().map(|l| l.to_vec()).collect::<Vec<_>>(),
        );
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&CLASS_IN.to_be_bytes());
        query
    }

    fn rcode(response: &[u8]) -> u8 {
        response[3] & 0x0F
    }

    fn ancount(response: &[u8]) -> u16 {
        u16::from_be_bytes([response[6], response[7]])
    }

    fn db1_labels() -> Vec<&'static [u8]> {
        vec![b"db-1", b"hznet", b"internal"]
    }

    #[test]
    fn a_query_for_known_node_answers_literal_ipv4() {
        let query = wire_query(0xA1B2, FLAG_RD, &db1_labels(), TYPE_A);
        let response = build_response(&query, &fixture(), "hznet.internal");
        assert_eq!(u16::from_be_bytes([response[0], response[1]]), 0xA1B2);
        assert_eq!(rcode(&response), 0, "NOERROR");
        assert_eq!(ancount(&response), 1);
        assert_eq!(&response[response.len() - 4..], &[100, 96, 0, 7]);
        assert_eq!(response[2] & 0x80, 0x80, "QR");
        assert_eq!(response[2] & 0x04, 0x04, "AA");
        assert_eq!(response[2] & 0x01, 0x01, "RD 回显");
    }

    #[test]
    fn aaaa_query_answers_literal_ipv6() {
        let query = wire_query(7, 0, &db1_labels(), TYPE_AAAA);
        let response = build_response(&query, &fixture(), "hznet.internal");
        assert_eq!(rcode(&response), 0);
        assert_eq!(ancount(&response), 1);
        assert_eq!(&response[response.len() - 16..], &fd12_ula().octets());
    }

    fn fd12_ula() -> Ipv6Addr {
        "fd12:3456:789a::6460:7".parse().unwrap()
    }

    #[test]
    fn foreign_suffix_is_refused() {
        let query = wire_query(9, 0, &[b"db-1", b"example", b"com"], TYPE_A);
        let response = build_response(&query, &fixture(), "hznet.internal");
        assert_eq!(rcode(&response), RCODE_REFUSED as u8);
        assert_eq!(ancount(&response), 0);
    }

    #[test]
    fn unknown_node_under_our_suffix_is_nxdomain() {
        let query = wire_query(10, 0, &[b"ghost", b"hznet", b"internal"], TYPE_A);
        let response = build_response(&query, &fixture(), "hznet.internal");
        assert_eq!(rcode(&response), RCODE_NXDOMAIN as u8);
        assert_eq!(ancount(&response), 0);
    }

    #[test]
    fn configured_suffix_decides_authority() {
        let nodes = fixture();
        let matched = wire_query(11, 0, &[b"db-1", b"corp", b"mesh"], TYPE_A);
        assert_eq!(
            rcode(&build_response(&matched, &nodes, "corp.mesh")),
            0,
            "自定义后缀内应答"
        );
        let stale = wire_query(12, 0, &db1_labels(), TYPE_A);
        assert_eq!(
            rcode(&build_response(&stale, &nodes, "corp.mesh")),
            RCODE_REFUSED as u8,
            "默认后缀已不再归本服务管辖"
        );
    }

    #[test]
    fn node_name_match_is_case_insensitive_and_echo_preserves_case() {
        let query = wire_query(13, 0, &[b"DB-1", b"HZNET", b"INTERNAL"], TYPE_A);
        let response = build_response(&query, &fixture(), "hznet.internal");
        assert_eq!(rcode(&response), 0);
        assert_eq!(ancount(&response), 1);
        assert!(
            response.windows(4).any(|w| w == b"DB-1"),
            "问题区按原始大小写回显"
        );
    }

    #[test]
    fn other_qtype_under_suffix_is_nodata() {
        let query = wire_query(14, 0, &db1_labels(), 0x000F);
        let response = build_response(&query, &fixture(), "hznet.internal");
        assert_eq!(rcode(&response), 0);
        assert_eq!(ancount(&response), 0);
    }

    #[test]
    fn garbage_packet_gets_formerr() {
        assert_eq!(
            rcode(&build_response(&[0xDE, 0xAD], &fixture(), "hznet.internal")),
            RCODE_FORMERR as u8
        );
        let no_question = {
            let mut msg = vec![0; 11];
            msg[4..6].copy_from_slice(&1u16.to_be_bytes());
            msg
        };
        assert_eq!(
            rcode(&build_response(&no_question, &fixture(), "hznet.internal")),
            RCODE_FORMERR as u8
        );
    }

    #[test]
    fn compressed_question_name_is_followed() {
        // 问题区 qname = "db-1" + 压缩指针 → 报文 offset 23 处的 hznet.internal；
        // hznet.internal labels 本身放在 question 之后（指针允许向后指任意位置）。
        let mut query = Vec::new();
        query.extend_from_slice(&15u16.to_be_bytes());
        query.extend_from_slice(&[0; 2]); // flags
        query.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // qdcount=1，其余 0
        query.extend_from_slice(b"\x04db-1"); // offset 12-16
        query.extend_from_slice(&[0xC0, 23]); // offset 17-18：指针 → offset 23
        query.extend_from_slice(&TYPE_A.to_be_bytes()); // offset 19-20
        query.extend_from_slice(&CLASS_IN.to_be_bytes()); // offset 21-22
        push_name(&mut query, &[b"hznet".to_vec(), b"internal".to_vec()]); // offset 23
        let response = build_response(&query, &fixture(), "hznet.internal");
        assert_eq!(rcode(&response), 0, "压缩指针 qname 应被正确展开匹配");
        assert_eq!(ancount(&response), 1);
    }

    const DNS_V4: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 53);
    const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 9);

    /// 客户端发往 `dst:dport` 的 IPv4 UDP 包（校验和留 0，解析不看它）。
    fn udp_packet(dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
        let mut out = vec![0x45, 0];
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 64, IPPROTO_UDP, 0, 0]);
        out.extend_from_slice(&CLIENT_V4.octets());
        out.extend_from_slice(&dst.octets());
        out.extend_from_slice(&40000u16.to_be_bytes());
        out.extend_from_slice(&dport.to_be_bytes());
        out.extend_from_slice(&((UDP_HEADER_LEN + payload.len()) as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn tun_query_to_dns_v4_port_53_is_recognized() {
        let payload = wire_query(1, 0, &db1_labels(), TYPE_A);
        let query = parse_tun_query(&udp_packet(DNS_V4, 53, &payload), DNS_V4).unwrap();
        assert_eq!(query.src, CLIENT_V4);
        assert_eq!(query.sport, 40000);
        assert_eq!(query.payload, payload);
    }

    #[test]
    fn non_dns_tun_packets_are_left_alone() {
        let payload = wire_query(1, 0, &db1_labels(), TYPE_A);
        let peer = Ipv4Addr::new(100, 96, 0, 7);
        assert!(
            parse_tun_query(&udp_packet(peer, 53, &payload), DNS_V4).is_none(),
            "对端的 53"
        );
        assert!(
            parse_tun_query(&udp_packet(DNS_V4, 5353, &payload), DNS_V4).is_none(),
            "非 53"
        );
        let mut tcp = udp_packet(DNS_V4, 53, &payload);
        tcp[9] = 6;
        assert!(parse_tun_query(&tcp, DNS_V4).is_none(), "TCP");
        let mut fragment = udp_packet(DNS_V4, 53, &payload);
        fragment[6] = 0x20; // MF
        assert!(parse_tun_query(&fragment, DNS_V4).is_none(), "分片");
        assert!(parse_tun_query(&[0x45, 0, 0], DNS_V4).is_none(), "截断的头");
    }

    #[test]
    fn tun_reply_swaps_endpoints_and_has_valid_checksums() {
        let payload = wire_query(1, 0, &db1_labels(), TYPE_A);
        let query = parse_tun_query(&udp_packet(DNS_V4, 53, &payload), DNS_V4).unwrap();
        let answer = build_response(&payload, &fixture(), "hznet.internal");
        let reply = build_tun_reply(&query, &answer);

        assert_eq!(&reply[12..16], &DNS_V4.octets(), "源 = dns_v4");
        assert_eq!(&reply[16..20], &CLIENT_V4.octets(), "目的 = 查询方");
        assert_eq!(
            u16::from_be_bytes([reply[2], reply[3]]) as usize,
            reply.len()
        );
        assert_eq!(
            fold_checksum(ones_complement_sum(0, &reply[..20])),
            0,
            "IP 校验和"
        );
        let udp = &reply[20..];
        assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), 53);
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 40000);
        assert_eq!(&udp[8..], answer.as_slice());
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&DNS_V4.octets());
        pseudo.extend_from_slice(&CLIENT_V4.octets());
        pseudo.extend_from_slice(&[0, IPPROTO_UDP]);
        pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
        assert_eq!(
            fold_checksum(ones_complement_sum(ones_complement_sum(0, &pseudo), udp)),
            0,
            "UDP 校验和"
        );
    }

    #[tokio::test]
    async fn tun_query_answered_locally_without_forwarding() {
        let payload = wire_query(5, 0, &db1_labels(), TYPE_A);
        let query = parse_tun_query(&udp_packet(DNS_V4, 53, &payload), DNS_V4).unwrap();
        let reply = answer_tun_query(&query, &fixture(), "hznet.internal", None).await;
        let answer = &reply[IPV4_HEADER_LEN + UDP_HEADER_LEN..];
        assert_eq!(rcode(answer), 0);
        assert_eq!(&answer[answer.len() - 4..], &[100, 96, 0, 7]);
    }
}
