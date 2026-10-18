//! `hz ping` 的数据面（FR-12）：应用层探针，不占用额外的 UDP socket。
//! 探针是发往对端 Node Address 固定端口的普通 UDP/IPv4 包，由引擎按当前
//! 路径（Relay 或直连）封装送达；对端 hzd 在解密包写回 TUN 之前拦截并原样
//! 应答。往返时延因此覆盖完整的数据面路径。请求与应答共用 magic，用类型
//! 字节区分，应答不再被回显（否则会无限往复）。

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex as StdMutex;

use hz_core::wire::SocketEngine;
use tokio::sync::oneshot;

/// 探针在 Node Address 上的固定 UDP 端口。
pub const PROBE_PORT: u16 = 51821;
const MAGIC: &[u8] = b"hzping1";
const TYPE_REQUEST: u8 = 0;
const TYPE_RESPONSE: u8 = 1;
/// magic + 类型字节 + 8 字节 nonce。
const PAYLOAD_LEN: usize = MAGIC.len() + 1 + 8;

/// 等待中的探针：nonce → 应答到达时被唤醒的一次性通道。
#[derive(Default)]
pub struct Probes {
    pending: StdMutex<HashMap<u64, oneshot::Sender<()>>>,
}

impl Probes {
    pub fn spawn(&self, nonce: u64) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .expect("probes poisoned")
            .insert(nonce, tx);
        rx
    }

    fn complete(&self, nonce: u64) {
        if let Some(tx) = self.pending.lock().expect("probes poisoned").remove(&nonce) {
            let _ = tx.send(());
        }
    }
}

struct ParsedProbe {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    response: bool,
    nonce: u64,
}

/// 解析一个发往本机探针端口的 UDP/IPv4 包；其余包返回 None。
fn parse(packet: &[u8]) -> Option<ParsedProbe> {
    let ihl = (packet.first()? & 0x0f) as usize * 4;
    if packet.len() < ihl + 8 || ihl < 20 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let udp = &packet[ihl..];
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    if dport != PROBE_PORT {
        return None;
    }
    let payload = &udp[8..];
    if payload.len() != PAYLOAD_LEN || !payload.starts_with(MAGIC) {
        return None;
    }
    let response = match payload[MAGIC.len()] {
        TYPE_REQUEST => false,
        TYPE_RESPONSE => true,
        _ => return None,
    };
    let nonce = u64::from_be_bytes(payload[MAGIC.len() + 1..].try_into().ok()?);
    Some(ParsedProbe {
        src,
        dst,
        response,
        nonce,
    })
}

/// 构造探针包（IPv4 + UDP 头，校验和留空：包不出本机数据面就再封装）。
pub fn build(src: Ipv4Addr, dst: Ipv4Addr, response: bool, nonce: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PAYLOAD_LEN);
    payload.extend_from_slice(MAGIC);
    payload.push(if response {
        TYPE_RESPONSE
    } else {
        TYPE_REQUEST
    });
    payload.extend_from_slice(&nonce.to_be_bytes());
    let total_len = 20 + 8 + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&1u16.to_be_bytes()); // 标识，帮助分片诊断
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF：探针不该分片
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    packet[20..22].copy_from_slice(&PROBE_PORT.to_be_bytes());
    packet[22..24].copy_from_slice(&PROBE_PORT.to_be_bytes());
    packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet[28..].copy_from_slice(&payload);
    packet
}

/// 解密包进 TUN 前的探针拦截：请求原样应答（走本机引擎的当前路径），
/// 应答唤醒等待方。返回 true 表示包已被 ping 消化，不再进 TUN。
pub async fn intercept(
    engine: &SocketEngine,
    probes: &Probes,
    own_v4: Ipv4Addr,
    packet: &[u8],
) -> bool {
    let Some(probe) = parse(packet) else {
        return false;
    };
    if probe.dst != own_v4 {
        return false;
    }
    if probe.response {
        probes.complete(probe.nonce);
    } else {
        engine
            .send_ip_packet(&build(own_v4, probe.src, true, probe.nonce))
            .await;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_packets_round_trip_through_parse() {
        let request = build(
            "100.96.0.1".parse().unwrap(),
            "100.96.0.2".parse().unwrap(),
            false,
            42,
        );
        let parsed = parse(&request).unwrap();
        assert_eq!(parsed.src, "100.96.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(parsed.dst, "100.96.0.2".parse::<Ipv4Addr>().unwrap());
        assert!(!parsed.response);
        assert_eq!(parsed.nonce, 42);

        let response = build(
            "100.96.0.2".parse().unwrap(),
            "100.96.0.1".parse().unwrap(),
            true,
            42,
        );
        let parsed = parse(&response).unwrap();
        assert!(parsed.response);
        assert_eq!(parsed.nonce, 42);
    }

    #[test]
    fn ordinary_udp_and_wrong_port_packets_are_ignored() {
        // 到探针端口但载荷不是探针协议。
        let mut noise = build(
            "100.96.0.1".parse().unwrap(),
            "100.96.0.2".parse().unwrap(),
            false,
            1,
        );
        noise[28] ^= 0xff; // 破坏 magic 首字节
        assert!(
            parse(&noise).is_none(),
            "载荷不属于探针协议的包不得被识别为探针"
        );
        // 普通端口的 UDP 包（DNS 之类）。
        let dns = [
            0x45u8, 0, 0, 40, 0, 0, 0, 0, 64, 17, 0, 0, 100, 96, 0, 2, 100, 96, 0, 53, 0x53, 0x53,
            0x35, 0x35, 0, 20, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        assert!(parse(&dns).is_none(), "非探针端口的包必须放行进 TUN");
    }

    #[tokio::test]
    async fn response_completes_pending_probe() {
        let probes = Probes::default();
        let rx = probes.spawn(7);
        probes.complete(7);
        rx.await.expect("应答必须唤醒等待方");
        probes.complete(7); // 迟到的重复应答不惊慌
    }
}
