//! 外层连接（Coordination Server / Relay / STUN）的域名解析（#23）。
//!
//! 第三方 TUN 类网络工具接管系统 DNS 时，会对任何域名返回 198.18.0.0/15
//! （RFC 2544 基准测试保留段）内的假地址，再由它自己代为连接。hzd 的外层
//! 流量绑定物理出口网卡（FR-7），连向假地址必然失败。这里把系统 DNS 的
//! 假地址结果视为无效，改为经物理出口网卡直接向引导 DNS 查询。

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// 单个引导 DNS 的查询超时。
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// 引导 DNS 的公共兜底：系统 DNS 都不可用时使用。
const PUBLIC_BOOTSTRAP: &[Ipv4Addr] =
    &[Ipv4Addr::new(223, 5, 5, 5), Ipv4Addr::new(119, 29, 29, 29)];

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

type SystemLookup = Box<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;
type BootstrapSource = Box<dyn Fn() -> Vec<SocketAddr> + Send + Sync>;

/// 198.18.0.0/15（含 IPv4 映射的 IPv6 形式）：不可能是真实公网地址，
/// 第三方 TUN 类网络工具用它分配假地址。
pub fn is_fake_ip(ip: &IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v4) => *v4,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return false,
        },
    };
    let [a, b, ..] = v4.octets();
    a == 198 && (b == 18 || b == 19)
}

/// 一次回退到引导 DNS 的记录，供 `hz status` 汇报（#25）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DnsFallback {
    /// Unix 秒。
    pub at: u64,
    pub host: String,
}

pub struct OuterResolver {
    bootstrap: BootstrapSource,
    system: SystemLookup,
    /// 每个域名最近一次有效解析结果：所有来源都失败时兜底。
    last_good: Mutex<HashMap<String, Vec<IpAddr>>>,
    /// 已就"改用引导 DNS"告警过的域名：每个域名只记一次，避免刷屏。
    warned_fallback: Mutex<HashSet<String>>,
    /// 正在沿用缓存的域名：连续失败期间只告警一次，解析恢复后清除。
    warned_stale: Mutex<HashSet<String>>,
    last_fallback: Mutex<Option<DnsFallback>>,
}

impl OuterResolver {
    /// 系统 DNS 查询经 `system` 注入（测试替换系统边界用）。
    pub fn with_system_lookup<F>(bootstrap: Vec<SocketAddr>, system: F) -> Self
    where
        F: Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    {
        Self::build(Box::new(move || bootstrap.clone()), Box::new(system))
    }

    fn build(bootstrap: BootstrapSource, system: SystemLookup) -> Self {
        Self {
            bootstrap,
            system,
            last_good: Mutex::new(HashMap::new()),
            warned_fallback: Mutex::new(HashSet::new()),
            warned_stale: Mutex::new(HashSet::new()),
            last_fallback: Mutex::new(None),
        }
    }

    /// 解析 `host:port`。IP 字面量直接返回；系统 DNS 给出真实地址即用之；
    /// 全是 198.18.0.0/15 假地址时改问引导 DNS；失败则沿用最近一次有效结果。
    /// 阻塞调用，异步上下文请经 `spawn_blocking`。
    pub fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let ips = match self.resolve_ips(host) {
            Ok(ips) => {
                self.lock_last_good().insert(host.to_string(), ips.clone());
                lock(&self.warned_stale).remove(host);
                ips
            }
            Err(error) => match self.lock_last_good().get(host).cloned() {
                Some(cached) => {
                    if lock(&self.warned_stale).insert(host.to_string()) {
                        tracing::warn!(%host, %error, "外层域名解析失败，沿用最近一次有效结果");
                    }
                    cached
                }
                None => return Err(error),
            },
        };
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }

    fn resolve_ips(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let answers: Vec<IpAddr> = (self.system)(host, 0)?.iter().map(SocketAddr::ip).collect();
        if answers.is_empty() || answers.iter().any(|ip| !is_fake_ip(ip)) {
            let real: Vec<IpAddr> = answers.into_iter().filter(|ip| !is_fake_ip(ip)).collect();
            if real.is_empty() {
                return Err(io::Error::other(format!("{host} 未解析出任何地址")));
            }
            return Ok(real);
        }
        *lock(&self.last_fallback) = Some(DnsFallback {
            at: unix_now(),
            host: host.to_string(),
        });
        if lock(&self.warned_fallback).insert(host.to_string()) {
            tracing::warn!(
                %host,
                fake = ?answers,
                "系统 DNS 返回 198.18.0.0/15 假地址（DNS 被第三方 TUN 类网络工具接管），改用引导 DNS"
            );
        }
        self.query_bootstrap(host)
    }

    /// 最近一次回退到引导 DNS；从未回退时为 None。
    pub fn last_fallback(&self) -> Option<DnsFallback> {
        lock(&self.last_fallback).clone()
    }

    fn lock_last_good(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<IpAddr>>> {
        lock(&self.last_good)
    }

    fn query_bootstrap(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let mut last_error = io::Error::other(format!("没有可用的引导 DNS 来解析 {host}"));
        for server in &(self.bootstrap)() {
            let mut ips = Vec::new();
            for qtype in [TYPE_A, TYPE_AAAA] {
                match query(*server, host, qtype) {
                    Ok(found) => ips.extend(found),
                    Err(error) => last_error = error,
                }
            }
            ips.retain(|ip| !is_fake_ip(ip));
            if !ips.is_empty() {
                return Ok(ips);
            }
        }
        Err(last_error)
    }
}

/// 进程级解析器：系统 DNS 用 getaddrinfo；引导 DNS 列表在每次需要回退时
/// 现查（`HZD_BOOTSTRAP_DNS` 优先，其次系统经 DHCP 获得的 DNS，最后公共
/// DNS），网络切换后 DHCP 下发的 DNS 变化也能跟上。
pub fn global() -> &'static OuterResolver {
    static RESOLVER: OnceLock<OuterResolver> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        OuterResolver::build(
            Box::new(|| {
                let configured = std::env::var("HZD_BOOTSTRAP_DNS").ok();
                bootstrap_servers(configured.as_deref(), &system_nameservers())
            }),
            Box::new(|host, port| {
                use std::net::ToSocketAddrs;
                Ok((host, port).to_socket_addrs()?.collect())
            }),
        )
    })
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().expect("outer_dns mutex poisoned")
}

/// 当前 Unix 秒。
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// 解析 `host:port` 或 `[ipv6]:port` 形式的外层地址（经 [`global`]）。阻塞调用。
pub fn resolve_host_port(target: &str) -> io::Result<Vec<SocketAddr>> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("地址缺少端口：{target}"),
        )
    };
    let (host, port) = target.rsplit_once(':').ok_or_else(invalid)?;
    let port: u16 = port.parse().map_err(|_| invalid())?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    global().resolve(host, port)
}

/// 引导 DNS 列表：`configured`（逗号分隔，`ip` 或 `ip:port`）非空时只用它；
/// 否则系统 DNS 在前、公共 DNS 兜底。端口缺省 53，结果去重。
pub fn bootstrap_servers(configured: Option<&str>, system: &[IpAddr]) -> Vec<SocketAddr> {
    let parse = |entry: &str| -> Option<SocketAddr> {
        let entry = entry.trim();
        entry.parse::<SocketAddr>().ok().or_else(|| {
            entry
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, 53))
        })
    };
    let configured: Vec<SocketAddr> = configured
        .map(|list| list.split(',').filter_map(parse).collect())
        .unwrap_or_default();
    let candidates = if configured.is_empty() {
        system
            .iter()
            .copied()
            .chain(PUBLIC_BOOTSTRAP.iter().map(|ip| IpAddr::V4(*ip)))
            .map(|ip| SocketAddr::new(ip, 53))
            .collect()
    } else {
        configured
    };
    let mut out: Vec<SocketAddr> = Vec::new();
    for addr in candidates {
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// 可作为引导 DNS 的地址：排除假地址、回环与链路本地（需要作用域，无法直接使用）。
fn usable_upstream(ip: &IpAddr) -> bool {
    let link_local = match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    };
    !is_fake_ip(ip) && !ip.is_loopback() && !ip.is_unspecified() && !link_local
}

fn push_unique(out: &mut Vec<IpAddr>, ip: IpAddr) {
    if usable_upstream(&ip) && !out.contains(&ip) {
        out.push(ip);
    }
}

/// `resolv.conf` 文本 → 可用的上游 DNS（跳过 systemd-resolved 的 127.0.0.53 存根等）。
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some("nameserver")
            && let Some(ip) = fields.next().and_then(|raw| raw.parse::<IpAddr>().ok())
        {
            push_unique(&mut out, ip);
        }
    }
    out
}

/// `scutil --dns` 文本 → 可用的上游 DNS。只取不带 `domain` 的通用解析器
/// （带 domain 的是分域解析器，如 HzNet 自己的 hznet.internal），跳过
/// 第三方 TUN 类网络工具的假 DNS 与回环地址。
pub fn parse_scutil_nameservers(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut block: Vec<IpAddr> = Vec::new();
    let mut scoped_to_domain = false;
    let flush = |block: &mut Vec<IpAddr>, scoped: bool, out: &mut Vec<IpAddr>| {
        if !scoped {
            for ip in block.drain(..) {
                push_unique(out, ip);
            }
        }
        block.clear();
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("resolver #") || line.starts_with("DNS configuration") {
            flush(&mut block, scoped_to_domain, &mut out);
            scoped_to_domain = false;
        } else if line.starts_with("domain") {
            scoped_to_domain = true;
        } else if line.starts_with("nameserver[")
            && let Some((_, value)) = line.split_once(':')
        {
            let value = value.trim();
            let value = value.split('%').next().unwrap_or(value);
            if let Ok(ip) = value.parse::<IpAddr>() {
                block.push(ip);
            }
        }
    }
    flush(&mut block, scoped_to_domain, &mut out);
    out
}

/// 本机经 DHCP 等获得的系统 DNS。
fn system_nameservers() -> Vec<IpAddr> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("scutil")
            .arg("--dns")
            .output()
            .map(|output| parse_scutil_nameservers(&String::from_utf8_lossy(&output.stdout)))
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "macos"))]
    {
        // systemd-resolved 的真实上游在 /run/systemd/resolve/resolv.conf；
        // /etc/resolv.conf 往往只有 127.0.0.53 存根。
        ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"]
            .iter()
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .map(|text| parse_resolv_conf(&text))
            .find(|servers| !servers.is_empty())
            .unwrap_or_default()
    }
}

/// 向 `server` 发一次 UDP 查询。目标不是回环地址时，socket 绑物理出口网卡，
/// 不让查询本身被第三方 TUN 类网络工具截走。
fn query(server: SocketAddr, host: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
    let local: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local)?;
    if !server.ip().is_loopback() {
        crate::netif::bind_to_physical_egress(&socket);
    }
    socket.set_read_timeout(Some(QUERY_TIMEOUT))?;
    let id = query_id();
    socket.send_to(&build_query(id, host, qtype)?, server)?;
    let mut buf = [0u8; 1500];
    loop {
        let (len, from) = socket.recv_from(&mut buf)?;
        if from != server {
            continue;
        }
        if let Some(ips) = parse_answers(&buf[..len], id) {
            return Ok(ips);
        }
    }
}

fn query_id() -> u16 {
    let mut bytes = [0u8; 2];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
    u16::from_be_bytes(bytes)
}

fn build_query(id: u16, host: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32 + host.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00]); // RD
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT=1
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("非法域名：{host}"),
            ));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&[0, 1]); // IN
    Ok(out)
}

/// 解析应答中的 A/AAAA 记录；id 不符或报文残缺时返回 None（当作噪声丢弃）。
fn parse_answers(msg: &[u8], id: u16) -> Option<Vec<IpAddr>> {
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != id || msg[2] & 0x80 == 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(msg, pos)? + 4;
    }
    let mut ips = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(msg, pos)?;
        let header = msg.get(pos..pos + 10)?;
        let rtype = u16::from_be_bytes([header[0], header[1]]);
        let rdlen = u16::from_be_bytes([header[8], header[9]]) as usize;
        let rdata = msg.get(pos + 10..pos + 10 + rdlen)?;
        match (rtype, rdlen) {
            (TYPE_A, 4) => ips.push(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            (TYPE_AAAA, 16) => {
                let octets: [u8; 16] = rdata.try_into().ok()?;
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos += 10 + rdlen;
    }
    Some(ips)
}

/// 跳过一个（可能含压缩指针的）名字，返回其后的位置。
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)?;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2);
        }
        pos += 1 + len as usize;
    }
}
