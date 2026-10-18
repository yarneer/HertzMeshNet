//! STUN（RFC 5389）Binding 的最小手写实现：客户端 + 服务端，只做 20 字节头
//! 与 XOR-MAPPED-ADDRESS，不引入完整 STUN 栈。客户端从 WireGuard 的共享
//! socket 发查询（单 socket 规则，ADR-0002）；该 socket 的收包循环归
//! [`crate::wire::SocketEngine`]，所以响应在那里按事务 id 路由回本模块的
//! [`StunRouter`]，再唤醒等待中的查询。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{Context, bail};
use rand_core::{OsRng, RngCore};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

/// RFC 5389 固定 magic cookie。
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const ATTR_MAPPED: u16 = 0x0001;
const ATTR_XOR_MAPPED: u16 = 0x0020;
const FAMILY_V4: u8 = 0x01;
const FAMILY_V6: u8 = 0x02;
const HEADER_LEN: usize = 20;

/// 查询等待响应的上限；超时视为 STUN 服务器不可达。
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

/// 生成 Binding Request（随机事务 id），返回 (事务 id, 报文)。
pub fn binding_request() -> ([u8; 12], Vec<u8>) {
    let mut txid = [0u8; 12];
    OsRng.fill_bytes(&mut txid);
    let mut message = Vec::with_capacity(HEADER_LEN);
    message.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message.extend_from_slice(&txid);
    (txid, message)
}

/// 服务端对一条请求构造 Binding Response，报告观测到的源地址。
/// 非 Binding Request（含残缺报文）返回 None。
pub fn binding_response(request: &[u8], observed: SocketAddr) -> Option<Vec<u8>> {
    if !is_binding_request(request) {
        return None;
    }
    let txid: [u8; 12] = request[8..20].try_into().expect("len checked above");
    let (family, xport, xaddr): (u8, [u8; 2], Vec<u8>) = match observed.ip() {
        IpAddr::V4(ip) => {
            let x = u32::from_be_bytes(ip.octets()) ^ MAGIC_COOKIE;
            (
                FAMILY_V4,
                (observed.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes(),
                x.to_be_bytes().to_vec(),
            )
        }
        IpAddr::V6(ip) => {
            let mut mask = MAGIC_COOKIE.to_be_bytes().to_vec();
            mask.extend_from_slice(&txid);
            let x: Vec<u8> = ip
                .octets()
                .iter()
                .zip(&mask)
                .map(|(byte, m)| byte ^ m)
                .collect();
            (
                FAMILY_V6,
                (observed.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes(),
                x,
            )
        }
    };
    let mut value = Vec::with_capacity(4 + xaddr.len());
    value.push(0);
    value.push(family);
    value.extend_from_slice(&xport);
    value.extend_from_slice(&xaddr);

    let mut message = Vec::with_capacity(HEADER_LEN + 4 + value.len());
    message.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
    message.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    message.extend_from_slice(&txid);
    message.extend_from_slice(&ATTR_XOR_MAPPED.to_be_bytes());
    message.extend_from_slice(&(value.len() as u16).to_be_bytes());
    message.extend_from_slice(&value);
    Some(message)
}

/// 解析 Binding Response 里的映射地址。优先 XOR-MAPPED-ADDRESS，
/// 兼容老实现的 MAPPED-ADDRESS；两者皆无返回 None。
pub fn parse_mapped_address(message: &[u8]) -> Option<SocketAddr> {
    if message.len() < HEADER_LEN {
        return None;
    }
    let message_type = u16::from_be_bytes([message[0], message[1]]);
    if message_type != BINDING_RESPONSE {
        return None;
    }
    let txid: [u8; 12] = message[8..20].try_into().expect("len checked above");
    let body_len = u16::from_be_bytes([message[2], message[3]]) as usize;
    let body = message.get(HEADER_LEN..HEADER_LEN + body_len)?;
    let mut offset = 0;
    while offset + 4 <= body.len() {
        let attr_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let attr_len = u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
        let value = body.get(offset + 4..offset + 4 + attr_len)?;
        if value.len() >= 4 {
            if let Some(addr) = decode_address(attr_type, value, &txid) {
                return Some(addr);
            }
        }
        offset += 4 + attr_len + attr_len % 4;
    }
    None
}

fn decode_address(attr_type: u16, value: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    let family = value[1];
    let port_raw = u16::from_be_bytes([value[2], value[3]]);
    match (attr_type, family) {
        (ATTR_XOR_MAPPED, FAMILY_V4) if value.len() >= 8 => {
            let xored = u32::from_be_bytes(value[4..8].try_into().expect("len checked"));
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(xored ^ MAGIC_COOKIE)),
                port_raw ^ (MAGIC_COOKIE >> 16) as u16,
            ))
        }
        (ATTR_XOR_MAPPED, FAMILY_V6) if value.len() >= 20 => {
            let mut mask = MAGIC_COOKIE.to_be_bytes().to_vec();
            mask.extend_from_slice(txid);
            let octets: [u8; 16] = value[4..20]
                .iter()
                .zip(&mask)
                .map(|(byte, m)| byte ^ m)
                .collect::<Vec<_>>()
                .try_into()
                .expect("16 bytes");
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port_raw ^ (MAGIC_COOKIE >> 16) as u16,
            ))
        }
        (ATTR_MAPPED, FAMILY_V4) if value.len() >= 8 => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(value[4], value[5], value[6], value[7])),
            port_raw,
        )),
        _ => None,
    }
}

/// 报文是否是发给我们的 Binding Response。WireGuard 报文首字节恒为 1..=4 且
/// 第 2..4 字节保留为 0；Binding Response 首两字节是 0x01 0x01 且带 magic
/// cookie，二者不会混淆。
pub fn is_binding_response(datagram: &[u8]) -> bool {
    datagram.len() >= HEADER_LEN
        && datagram[0] == 0x01
        && datagram[1] == 0x01
        && u32::from_be_bytes(datagram[4..8].try_into().expect("len checked")) == MAGIC_COOKIE
}

fn is_binding_request(datagram: &[u8]) -> bool {
    datagram.len() >= HEADER_LEN
        && u16::from_be_bytes([datagram[0], datagram[1]]) == BINDING_REQUEST
        && u32::from_be_bytes(datagram[4..8].try_into().expect("len checked")) == MAGIC_COOKIE
}

/// 共享 socket 上的 STUN 事务路由：查询先登记事务 id，收包循环把响应交给
/// [`StunRouter::dispatch`]，匹配的事务被唤醒。
#[derive(Default)]
pub struct StunRouter {
    pending: StdMutex<HashMap<[u8; 12], oneshot::Sender<SocketAddr>>>,
}

impl StunRouter {
    /// 从 socket 发一条查询并等待映射地址。socket 必须是收包循环归属的同一
    /// 个（响应由循环转交，不与本函数竞争 recv）。
    pub async fn query(
        self: &Arc<Self>,
        sock: &UdpSocket,
        server: SocketAddr,
    ) -> anyhow::Result<SocketAddr> {
        let (txid, request) = binding_request();
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .expect("stun pending poisoned")
            .insert(txid, tx);
        // 登记失败时必须清掉，否则同事务 id 的迟到响应会匹配到死等待。
        let cleanup = |router: &Arc<Self>| {
            router
                .pending
                .lock()
                .expect("stun pending poisoned")
                .remove(&txid);
        };
        sock.send_to(&request, server)
            .await
            .with_context(|| format!("stun request send to {server} failed"))?;
        let mapped = tokio::time::timeout(RESPONSE_TIMEOUT, rx).await;
        cleanup(self);
        match mapped {
            Ok(Ok(addr)) => Ok(addr),
            Ok(Err(_)) => bail!("stun 事务在收到响应前被放弃（txid {txid:02x?}）"),
            Err(_) => bail!(
                "stun 查询 {server} 超时（{}ms）",
                RESPONSE_TIMEOUT.as_millis()
            ),
        }
    }

    /// 收包循环调用：是本路由器的 Binding Response 就投递并返回 true。
    pub fn dispatch(&self, datagram: &[u8]) -> bool {
        if !is_binding_response(datagram) {
            return false;
        }
        let Ok(txid) = datagram[8..20].try_into() else {
            return false;
        };
        let txid: [u8; 12] = txid;
        let waiter = self
            .pending
            .lock()
            .expect("stun pending poisoned")
            .remove(&txid);
        if let Some(waiter) = waiter {
            match parse_mapped_address(datagram) {
                Some(addr) => {
                    let _ = waiter.send(addr);
                    return true;
                }
                None => {
                    tracing::warn!("stun response carried no usable mapped address");
                }
            }
        }
        false
    }
}

/// STUN 服务端常驻循环：回答 Binding Request，其余报文丢弃。
pub async fn serve(sock: Arc<UdpSocket>) -> anyhow::Result<()> {
    let local = sock.local_addr().context("stun socket has no local addr")?;
    tracing::info!(%local, "stun server listening");
    let mut buf = vec![0u8; 65536];
    loop {
        let (len, from) = match sock.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(error) => {
                tracing::warn!(%error, "stun server recv failed, stopping");
                return Err(error.into());
            }
        };
        if let Some(response) = binding_response(&buf[..len], from) {
            if let Err(error) = sock.send_to(&response, from).await {
                tracing::warn!(%from, %error, "stun server reply failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_round_trips_v4_and_v6_addresses() {
        for observed in ["203.0.113.9:40123", "[2001:db8::5]:51820"] {
            let observed: SocketAddr = observed.parse().unwrap();
            let (txid, request) = binding_request();
            let response = binding_response(&request, observed).unwrap();
            assert_eq!(parse_mapped_address(&response), Some(observed));
            assert!(is_binding_response(&response));
            assert!(!is_binding_response(&request));
            assert_eq!(&response[8..20], &txid[..]);
        }
    }

    #[test]
    fn plain_mapped_address_is_accepted_for_compatibility() {
        // 老 STUN 服务器只回 MAPPED-ADDRESS（非 XOR）。
        let mut message = Vec::new();
        message.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        message.extend_from_slice(&12u16.to_be_bytes());
        message.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        message.extend_from_slice(&[0u8; 12]);
        message.extend_from_slice(&ATTR_MAPPED.to_be_bytes());
        message.extend_from_slice(&8u16.to_be_bytes());
        message.push(0);
        message.push(FAMILY_V4);
        message.extend_from_slice(&19851u16.to_be_bytes());
        message.extend_from_slice(&[192, 0, 2, 10]);
        assert_eq!(
            parse_mapped_address(&message),
            Some("192.0.2.10:19851".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn router_matches_response_by_transaction_id() {
        let router = Arc::new(StunRouter::default());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        // 应答方先就位再发起查询，避免首包撞上端口未监听。
        let echo = Arc::new(UdpSocket::bind(server).await.unwrap());
        let responder = {
            let echo = echo.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 128];
                let (len, from) = echo.recv_from(&mut buf).await.unwrap();
                assert!(is_binding_request(&buf[..len]));
                let reply = binding_response(&buf[..len], from).unwrap();
                echo.send_to(&reply, from).await.unwrap();
            })
        };
        let query = {
            let router = router.clone();
            let sock = sock.clone();
            tokio::spawn(async move { router.query(&sock, server).await })
        };
        // 收包泵模拟 SocketEngine 的 run 循环：把响应按事务 id 交回路由器。
        let pump = {
            let sock = sock.clone();
            let router = router.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                while let Ok((len, _)) = sock.recv_from(&mut buf).await {
                    router.dispatch(&buf[..len]);
                }
            })
        };
        responder.await.unwrap();
        let mapped = query.await.unwrap().unwrap();
        pump.abort();
        assert_eq!(mapped.port(), sock.local_addr().unwrap().port());
        assert!(mapped.ip().is_loopback());
    }

    #[tokio::test]
    async fn late_response_for_unknown_transaction_is_ignored() {
        let router = StunRouter::default();
        let (_, request) = binding_request();
        let response = binding_response(&request, "203.0.113.7:4000".parse().unwrap()).unwrap();
        assert!(!router.dispatch(&response));
    }
}
