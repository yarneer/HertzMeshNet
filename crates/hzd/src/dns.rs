//! 本地 DNS 应答（FR-5 / A2）：hzd 在保留地址 100.96.0.53:53 上应答
//! `<NodeName>.<suffix>` 的 A/AAAA 查询，数据来自 Network Map 缓存的实时快照。
//! 系统接入是声明式配置而不是一串命令：systemd-resolved 环境写
//! conf.d/hznet.conf 分域接管（`Domains=~<suffix>`，只吃 HzNet 后缀）；
//! 无 systemd 的容器/测试环境在 HZD_DNS_RESOLVCONF_FALLBACK=1 显式要求下才
//! 重写 /etc/resolv.conf，停止时逐字节还原；两者之外的文件一概不碰。
//! 线格式按 RFC 1035 手写编码（只做 应答 A/AAAA + REFUSED/NXDOMAIN，
//! 不递归），垃圾报文回 FORMERR。

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use hz_core::dns::{DNS_BIND_V4, DNS_PORT};
use hz_core::map::{MapNode, NetworkMapCache};

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

/// 在指定地址起 UDP + TCP 应答循环（测试可用 127.0.0.1:0），返回实际绑定地址。
pub async fn spawn_responder(
    addr: SocketAddr,
    cache: Arc<NetworkMapCache>,
    suffix: String,
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
        async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((len, peer)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                let response = build_response(&buf[..len], &cache.snapshot(), &suffix);
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
                tokio::spawn(async move {
                    while let Some(query) = read_tcp_message(&mut stream).await {
                        let response = build_response(&query, &cache.snapshot(), &suffix);
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

/// systemd-resolved 分域接管的声明式配置；render 是纯函数，字面量可测。
pub struct ResolvedConfig {
    pub suffix: String,
    pub dns_addr: Ipv4Addr,
}

impl ResolvedConfig {
    pub fn render(&self) -> String {
        format!(
            "[Resolve]\nDNS={}\nDomains=~{}\n",
            self.dns_addr, self.suffix
        )
    }
}

/// resolv.conf 显式退路的生成内容：本服务 nameserver 置顶（后缀内应答、
/// 后缀外 REFUSED 让 glibc 顺序落到原 nameserver），search 合并进后缀。
/// 纯函数，字面量可测。
pub fn fallback_resolvconf_content(previous: &str, dns: Ipv4Addr, suffix: &str) -> String {
    let mut out = format!("nameserver {dns}\n");
    let mut search = vec![suffix.to_string()];
    for line in previous.lines() {
        let mut parts = line.split_whitespace();
        match parts.next().unwrap_or_default() {
            keyword
                if keyword.eq_ignore_ascii_case("search")
                    || keyword.eq_ignore_ascii_case("domain") =>
            {
                search.extend(parts.map(str::to_string));
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out.push_str(&format!("search {}\n", search.join(" ")));
    out
}

/// 系统接入点；测试用临时目录注入。
pub struct SystemDnsPaths {
    pub resolved_conf: PathBuf,
    pub resolv_conf: PathBuf,
}

impl SystemDnsPaths {
    pub fn system() -> Self {
        Self {
            resolved_conf: PathBuf::from("/etc/systemd/resolved/conf.d/hznet.conf"),
            resolv_conf: PathBuf::from("/etc/resolv.conf"),
        }
    }
}

enum Integration {
    /// conf.d/hznet.conf：启动前不存在则停止时删除，存在则原样还原。
    ResolvedConf {
        path: PathBuf,
        previous: Option<Vec<u8>>,
    },
    /// HZD_DNS_RESOLVCONF_FALLBACK=1 的容器退路：停止时逐字节还原。
    ResolvConfFallback {
        path: PathBuf,
        previous: Vec<u8>,
    },
    None,
}

impl Integration {
    fn apply(paths: &SystemDnsPaths, config: &ResolvedConfig, allow_fallback: bool) -> Integration {
        let Some(conf_dir) = paths.resolved_conf.parent().map(PathBuf::from) else {
            return Integration::None;
        };
        if conf_dir.exists() {
            let previous = std::fs::read(&paths.resolved_conf).ok();
            let write = std::fs::create_dir_all(&conf_dir)
                .and_then(|()| std::fs::write(&paths.resolved_conf, config.render()));
            match write {
                Ok(()) => {
                    tracing::info!(
                        path = %paths.resolved_conf.display(),
                        "systemd-resolved domain-split config written"
                    );
                    flush_resolved_caches();
                    return Integration::ResolvedConf {
                        path: paths.resolved_conf.clone(),
                        previous,
                    };
                }
                Err(error) => {
                    tracing::warn!(%error, "write systemd-resolved config failed");
                }
            }
        }
        if allow_fallback {
            match std::fs::read_to_string(&paths.resolv_conf) {
                Ok(previous) => {
                    let content =
                        fallback_resolvconf_content(&previous, config.dns_addr, &config.suffix);
                    match std::fs::write(&paths.resolv_conf, &content) {
                        Ok(()) => {
                            tracing::info!(
                                path = %paths.resolv_conf.display(),
                                "resolv.conf fallback written (explicit env)"
                            );
                            return Integration::ResolvConfFallback {
                                path: paths.resolv_conf.clone(),
                                previous: previous.into_bytes(),
                            };
                        }
                        Err(error) => {
                            tracing::warn!(%error, "write resolv.conf fallback failed");
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "read resolv.conf failed, skip fallback");
                }
            }
        }
        Integration::None
    }

    fn restore(self) -> anyhow::Result<()> {
        match self {
            Integration::ResolvedConf { path, previous } => {
                match previous {
                    Some(bytes) => std::fs::write(&path, bytes)?,
                    None => match std::fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    },
                }
                flush_resolved_caches();
            }
            Integration::ResolvConfFallback { path, previous } => {
                std::fs::write(&path, previous)?;
            }
            Integration::None => {}
        }
        Ok(())
    }
}

fn flush_resolved_caches() {
    match std::process::Command::new("resolvectl")
        .args(["flush-caches"])
        .output()
    {
        Ok(output) if output.status.success() => {}
        _ => tracing::debug!("resolvectl flush-caches unavailable, skipped"),
    }
}

/// 信号/Drop 双路径的还原闸门；restore 幂等。
struct ShutdownGuard(StdMutex<Option<Integration>>);

impl ShutdownGuard {
    fn restore(&self) {
        if let Some(integration) = self.0.lock().expect("dns guard poisoned").take() {
            if let Err(error) = integration.restore() {
                tracing::warn!(%error, "restore system dns config failed");
            }
        }
    }
}

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

/// 生产入口：辅助地址挂 hz0 → 双栈应答 → 系统接入 → 信号守护。幂等。
pub async fn spawn(cache: Arc<NetworkMapCache>) -> anyhow::Result<()> {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let suffix = hz_core::dns::dns_suffix();
    let config = ResolvedConfig {
        suffix: suffix.clone(),
        dns_addr: DNS_BIND_V4,
    };
    hz_core::tun::add_secondary_addr(&DNS_BIND_V4).with_context(|| {
        format!("hz0 辅助地址 {DNS_BIND_V4}/32 添加失败（hz0 未就绪则本地 DNS 应答不可用）")
    })?;
    let addr = SocketAddr::from((DNS_BIND_V4, DNS_PORT));
    let bound = match spawn_responder(addr, cache, suffix.clone()).await {
        Ok(bound) => bound,
        Err(error) => {
            let _ = hz_core::tun::remove_secondary_addr(&DNS_BIND_V4);
            return Err(error);
        }
    };
    tracing::info!(%bound, suffix = %suffix, "local dns responder started");
    let allow_fallback = matches!(
        std::env::var("HZD_DNS_RESOLVCONF_FALLBACK").as_deref(),
        Ok("1") | Ok("true")
    );
    let integration = Integration::apply(&SystemDnsPaths::system(), &config, allow_fallback);
    spawn_signal_task(Arc::new(ShutdownGuard(StdMutex::new(Some(integration)))));
    Ok(())
}

/// SIGTERM/SIGINT 先还原系统配置再以默认处置退出；正常退出路径由 Drop 兜底。
#[cfg(unix)]
fn spawn_signal_task(guard: Arc<ShutdownGuard>) {
    tokio::spawn(async move {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => return,
            };
        let mut interrupt =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
                Ok(signal) => signal,
                Err(_) => return,
            };
        let signal_number = tokio::select! {
            _ = terminate.recv() => libc::SIGTERM,
            _ = interrupt.recv() => libc::SIGINT,
        };
        guard.restore();
        tracing::info!(signal = signal_number, "dns config restored, terminating");
        unsafe {
            libc::signal(signal_number, libc::SIG_DFL);
            libc::raise(signal_number);
        }
        std::process::exit(128 + signal_number);
    });
}

#[cfg(not(unix))]
fn spawn_signal_task(_guard: Arc<ShutdownGuard>) {}

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

    #[test]
    fn resolved_config_renders_literal_content() {
        let config = ResolvedConfig {
            suffix: "corp.mesh".to_string(),
            dns_addr: Ipv4Addr::new(100, 96, 0, 53),
        };
        assert_eq!(
            config.render(),
            "[Resolve]\nDNS=100.96.0.53\nDomains=~corp.mesh\n"
        );
    }

    #[test]
    fn fallback_resolvconf_content_merges_search_and_keeps_other_lines() {
        let previous = "nameserver 127.0.0.11\nsearch corp.docker\noptions ndots:0\n";
        assert_eq!(
            fallback_resolvconf_content(previous, Ipv4Addr::new(100, 96, 0, 53), "hznet.internal"),
            "nameserver 100.96.0.53\nnameserver 127.0.0.11\noptions ndots:0\nsearch hznet.internal corp.docker\n"
        );
    }

    #[test]
    fn integration_writes_then_removes_hznet_conf_without_touching_neighbors() {
        let dir = tempfile::tempdir().unwrap();
        let conf_dir = dir.path().join("conf.d");
        std::fs::create_dir_all(&conf_dir).unwrap();
        std::fs::write(conf_dir.join("other.conf"), "keep me\n").unwrap();
        let paths = SystemDnsPaths {
            resolved_conf: conf_dir.join("hznet.conf"),
            resolv_conf: dir.path().join("resolv.conf"),
        };
        let config = ResolvedConfig {
            suffix: "hznet.internal".to_string(),
            dns_addr: DNS_BIND_V4,
        };

        let integration = Integration::apply(&paths, &config, false);
        assert_eq!(
            std::fs::read_to_string(&paths.resolved_conf).unwrap(),
            config.render()
        );
        integration.restore().unwrap();

        assert!(!paths.resolved_conf.exists(), "停止后 hznet.conf 应被删除");
        assert_eq!(
            std::fs::read_to_string(conf_dir.join("other.conf")).unwrap(),
            "keep me\n",
            "无关的 resolved 配置不得被动"
        );
    }

    #[test]
    fn integration_restores_preexisting_hznet_conf_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let conf_dir = dir.path().join("conf.d");
        std::fs::create_dir_all(&conf_dir).unwrap();
        std::fs::write(conf_dir.join("hznet.conf"), "[Resolve]\nDNS=10.0.0.1\n").unwrap();
        let paths = SystemDnsPaths {
            resolved_conf: conf_dir.join("hznet.conf"),
            resolv_conf: dir.path().join("resolv.conf"),
        };
        let config = ResolvedConfig {
            suffix: "hznet.internal".to_string(),
            dns_addr: DNS_BIND_V4,
        };

        Integration::apply(&paths, &config, false)
            .restore()
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&paths.resolved_conf).unwrap(),
            "[Resolve]\nDNS=10.0.0.1\n",
            "启动前就存在的 hznet.conf 停止时逐字节还原"
        );
    }

    #[test]
    fn fallback_integration_rewrites_and_restores_resolv_conf_only_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        let original = "nameserver 127.0.0.11\noptions ndots:0\n";
        std::fs::write(dir.path().join("resolv.conf"), original).unwrap();
        let paths = SystemDnsPaths {
            resolved_conf: dir.path().join("conf.d").join("hznet.conf"),
            resolv_conf: dir.path().join("resolv.conf"),
        };
        let config = ResolvedConfig {
            suffix: "hznet.internal".to_string(),
            dns_addr: DNS_BIND_V4,
        };

        assert!(matches!(
            Integration::apply(&paths, &config, false),
            Integration::None
        ));
        assert_eq!(
            std::fs::read_to_string(&paths.resolv_conf).unwrap(),
            original,
            "未显式要求退路时绝不改 resolv.conf"
        );

        Integration::apply(&paths, &config, true).restore().unwrap();
        assert_eq!(
            std::fs::read_to_string(&paths.resolv_conf).unwrap(),
            original,
            "停止后 resolv.conf 逐字节还原"
        );
    }
}
