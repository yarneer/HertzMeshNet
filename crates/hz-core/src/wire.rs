//! 用户态 WireGuard 引擎（boringtun）。领域结构：PeerTable 以 NodeId 为主键，
//! 每个 Peer 持有一个 noise::Tunn，加两张派生索引（目标地址→NodeId、
//! WireGuard 接收索引→NodeId）。UDP socket 由 [`SocketEngine`] 持有并独占，
//! 与后续打洞（#8）共用；`Engine` 本身不碰网络，可在任意平台做单元测试。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{Context, bail};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// WireGuard 数据报与 IP 包的统一缓冲上限（UDP 数据报上限 64 KiB）。
const MAX_DATAGRAM: usize = 65536;

/// boringtun 定期保活间隔（秒）。
const KEEPALIVE_SECS: u16 = 25;

/// WireGuard 消息类型字节。
const MSG_HANDSHAKE_INIT: u8 = 1;
const MSG_HANDSHAKE_RESPONSE: u8 = 2;

/// Network Map 里一个对端的数据面描述。
#[derive(Debug, Clone)]
pub struct PeerSpec {
    pub node_id: String,
    pub node_key_pub: [u8; 32],
    pub endpoints: Vec<SocketAddr>,
    /// 该 Node 的 Node Address（v4 与 ULA v6），本机发往这些地址的包都路由给它。
    pub dst_addrs: Vec<IpAddr>,
}

/// 要发往网络的数据报。primary 失败时按 alternates 顺序重试。
#[derive(Debug, Clone)]
pub struct NetworkSend {
    pub node_id: String,
    pub primary: SocketAddr,
    pub alternates: Vec<SocketAddr>,
    pub datagram: Vec<u8>,
}

/// 引擎一次处理产生的输出。
#[derive(Debug, Default)]
pub struct EngineOutput {
    pub to_network: Vec<NetworkSend>,
    /// 解密出的明文 IP 包，应写进 TUN。
    pub to_tunnel: Vec<Vec<u8>>,
}

struct Peer {
    node_key_pub: [u8; 32],
    /// 偏好序的 Endpoint 列表，index 0 是当前最佳。
    endpoints: Vec<SocketAddr>,
    tunn: Tunn,
    dst_addrs: Vec<IpAddr>,
}

enum Step {
    Network(Vec<u8>),
    Tunnel(Vec<u8>),
    Stop,
}

fn step_result(result: TunnResult<'_>) -> Step {
    match result {
        TunnResult::WriteToNetwork(bytes) => Step::Network(bytes.to_vec()),
        TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
            Step::Tunnel(bytes.to_vec())
        }
        TunnResult::Done => Step::Stop,
        TunnResult::Err(error) => {
            tracing::debug!(?error, "wireguard tunnel error");
            Step::Stop
        }
    }
}

/// 纯逻辑的 WireGuard 引擎：不持有 socket、不依赖 TUN。
pub struct Engine {
    own_secret: StaticSecret,
    peers: HashMap<String, Peer>,
    by_dst: HashMap<IpAddr, String>,
    by_index: HashMap<u32, String>,
    next_local_index: u32,
}

impl Engine {
    pub fn new(own_secret: StaticSecret) -> Self {
        Self {
            own_secret,
            peers: HashMap::new(),
            by_dst: HashMap::new(),
            by_index: HashMap::new(),
            // 0 保留给"未分配"；boringtun 内部把 index 左移 8 位派生会话索引。
            next_local_index: 1,
        }
    }

    /// 用整份 Network Map 对账：新增/更新在册的对端，移除消失的对端。
    pub fn reconcile(&mut self, specs: Vec<PeerSpec>) {
        for spec in &specs {
            self.configure(spec.clone());
        }
        let stale: Vec<String> = self
            .peers
            .keys()
            .filter(|id| !specs.iter().any(|spec| &spec.node_id == *id))
            .cloned()
            .collect();
        for id in stale {
            self.remove_peer(&id);
        }
    }

    /// 新增或更新一个对端。Node Key 变化意味着对端轮换了密钥，必须重建会话。
    pub fn configure(&mut self, spec: PeerSpec) {
        let existing_key = self.peers.get(&spec.node_id).map(|p| p.node_key_pub);
        if existing_key == Some(spec.node_key_pub) {
            let peer = self.peers.get_mut(&spec.node_id).expect("checked above");
            let fresh = std::mem::take(&mut peer.endpoints);
            peer.endpoints = merge_endpoints(fresh, spec.endpoints);
            peer.dst_addrs = spec.dst_addrs;
        } else {
            let tunn = Tunn::new(
                self.own_secret.clone(),
                PublicKey::from(spec.node_key_pub),
                None,
                Some(KEEPALIVE_SECS),
                self.next_local_index,
                None,
            );
            self.next_local_index += 1;
            let old = self.peers.insert(
                spec.node_id.clone(),
                Peer {
                    node_key_pub: spec.node_key_pub,
                    endpoints: spec.endpoints,
                    tunn,
                    dst_addrs: spec.dst_addrs,
                },
            );
            if old.is_some() {
                self.by_index.retain(|_, owner| owner != &spec.node_id);
            }
        }
        for dst in self
            .peers
            .get(&spec.node_id)
            .expect("just configured")
            .dst_addrs
            .clone()
        {
            self.by_dst.insert(dst, spec.node_id.clone());
        }
    }

    pub fn remove_peer(&mut self, node_id: &str) {
        if let Some(peer) = self.peers.remove(node_id) {
            for dst in &peer.dst_addrs {
                if self.by_dst.get(dst).is_some_and(|owner| owner == node_id) {
                    self.by_dst.remove(dst);
                }
            }
            self.by_index.retain(|_, owner| owner != node_id);
        }
    }

    /// TUN 出方向的明文 IP 包：按目的地址找到对端并封装。
    /// 目的地址不属于任何对端时静默丢弃（隧道不承载 HzNet 段以外的流量）。
    pub fn send_ip_packet(&mut self, packet: &[u8]) -> EngineOutput {
        let mut out = EngineOutput::default();
        let Some(dst) = Tunn::dst_address(packet) else {
            tracing::warn!(len = packet.len(), "drop non-IP packet from tun");
            return out;
        };
        let Some(node_id) = self.by_dst.get(&dst).cloned() else {
            tracing::debug!(%dst, "drop packet to unknown destination");
            return out;
        };
        let mut scratch = vec![0u8; MAX_DATAGRAM];
        let result = self
            .peers
            .get_mut(&node_id)
            .expect("by_dst 与 peers 一致")
            .tunn
            .encapsulate(packet, &mut scratch);
        if let Step::Network(datagram) = step_result(result) {
            self.register_own_index(&node_id, &datagram);
            if let Some(send) = self.network_send(&node_id, datagram) {
                out.to_network.push(send);
            }
        }
        out
    }

    /// UDP 入方向的一个 WireGuard 数据报。无法归队（未知接收索引、无对端能解密）
    /// 时静默丢弃。
    pub fn handle_udp(&mut self, from: SocketAddr, datagram: &[u8]) -> EngineOutput {
        let mut out = EngineOutput::default();
        let Some(&msg_type) = datagram.first() else {
            return out;
        };
        let mut scratch = vec![0u8; MAX_DATAGRAM];

        if msg_type == MSG_HANDSHAKE_INIT {
            // 握手发起包不带能定位对端的索引，逐对端尝试解密，成功即归队。
            let mut found = None;
            for candidate in self.peers.keys().cloned().collect::<Vec<_>>() {
                let result = self
                    .peers
                    .get_mut(&candidate)
                    .expect("iterating live peers")
                    .tunn
                    .decapsulate(Some(from.ip()), datagram, &mut scratch);
                if let TunnResult::WriteToNetwork(bytes) = result {
                    found = Some((candidate, bytes.to_vec()));
                    break;
                }
            }
            let Some((node_id, response)) = found else {
                tracing::debug!(%from, "drop handshake initiation from unknown peer");
                return out;
            };
            self.prefer_endpoint(&node_id, from);
            self.register_own_index(&node_id, &response);
            out.to_network.push(NetworkSend {
                node_id,
                primary: from,
                alternates: Vec::new(),
                datagram: response,
            });
            return out;
        }

        let index = datagram
            .get(4..8)
            .map(|raw| u32::from_le_bytes(raw.try_into().expect("4 bytes")));
        let Some(node_id) = index.and_then(|index| self.by_index.get(&index).cloned()) else {
            tracing::debug!(%msg_type, %from, "drop wireguard datagram for unknown index");
            return out;
        };
        self.prefer_endpoint(&node_id, from);
        let result = self
            .peers
            .get_mut(&node_id)
            .expect("by_index 与 peers 一致")
            .tunn
            .decapsulate(Some(from.ip()), datagram, &mut scratch);
        // 解密方一侧可能排队了多个待发数据报，按 boringtun 契约用空数据报排空。
        let mut pending = Some(step_result(result));
        while let Some(step) = pending.take() {
            match step {
                Step::Network(datagram) => {
                    self.register_own_index(&node_id, &datagram);
                    out.to_network.push(NetworkSend {
                        node_id: node_id.clone(),
                        primary: from,
                        alternates: Vec::new(),
                        datagram,
                    });
                }
                Step::Tunnel(packet) => out.to_tunnel.push(packet),
                Step::Stop => break,
            }
            let next = self
                .peers
                .get_mut(&node_id)
                .expect("by_index 与 peers 一致")
                .tunn
                .decapsulate(Some(from.ip()), &[], &mut scratch);
            pending = Some(step_result(next));
        }
        out
    }

    /// 定时器推进：重握手、重传与保活。hzd 以亚秒级间隔调用。
    pub fn tick(&mut self) -> EngineOutput {
        let mut out = EngineOutput::default();
        let mut scratch = vec![0u8; MAX_DATAGRAM];
        for node_id in self.peers.keys().cloned().collect::<Vec<_>>() {
            let result = self
                .peers
                .get_mut(&node_id)
                .expect("iterating live peers")
                .tunn
                .update_timers(&mut scratch);
            if let Step::Network(datagram) = step_result(result) {
                self.register_own_index(&node_id, &datagram);
                if let Some(send) = self.network_send(&node_id, datagram) {
                    out.to_network.push(send);
                }
            }
        }
        out
    }

    /// 偏好序的 Endpoint 候选（发送失败时按序回退）。
    pub fn endpoint_candidates(&self, node_id: &str) -> Vec<SocketAddr> {
        self.peers
            .get(node_id)
            .map(|peer| peer.endpoints.clone())
            .unwrap_or_default()
    }

    /// 把 addr 提升为该对端的最佳 Endpoint（来源：对端漫游后我们收到包的地址）。
    pub fn prefer_endpoint(&mut self, node_id: &str, addr: SocketAddr) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.endpoints = merge_endpoints(std::mem::take(&mut peer.endpoints), vec![addr]);
        }
    }

    /// 各对端最近一次握手距今的时间；None 表示尚未握手。
    pub fn handshake_ages(&self) -> HashMap<String, Option<Duration>> {
        self.peers
            .iter()
            .map(|(id, peer)| (id.clone(), peer.tunn.time_since_last_handshake()))
            .collect()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    fn preferred_endpoint(&self, node_id: &str) -> Option<SocketAddr> {
        self.peers
            .get(node_id)
            .and_then(|p| p.endpoints.first().copied())
    }

    fn network_send(&self, node_id: &str, datagram: Vec<u8>) -> Option<NetworkSend> {
        let primary = self.preferred_endpoint(node_id)?;
        let alternates = self
            .endpoint_candidates(node_id)
            .into_iter()
            .filter(|addr| *addr != primary)
            .collect();
        Some(NetworkSend {
            node_id: node_id.to_owned(),
            primary,
            alternates,
            datagram,
        })
    }

    /// 我们发出的握手包在 [4..8] 携带自己的本地索引，
    /// 对端后续数据将用它作为接收索引，登记后才能完成入方向分发。
    fn register_own_index(&mut self, node_id: &str, datagram: &[u8]) {
        let Some(&msg_type) = datagram.first() else {
            return;
        };
        if msg_type != MSG_HANDSHAKE_INIT && msg_type != MSG_HANDSHAKE_RESPONSE {
            return;
        }
        let Some(raw) = datagram.get(4..8) else {
            return;
        };
        let index = u32::from_le_bytes(raw.try_into().expect("4 bytes"));
        self.by_index.insert(index, node_id.to_owned());
    }
}

/// 合并 Endpoint：新地址提到最前，已有地址去重，保持偏好序。
fn merge_endpoints(mut preferred: Vec<SocketAddr>, fresh: Vec<SocketAddr>) -> Vec<SocketAddr> {
    for addr in fresh {
        preferred.retain(|existing| *existing != addr);
        preferred.insert(0, addr);
    }
    preferred
}

/// 持有唯一 UDP socket 的引擎外壳：socket 归它所有（#8 打洞复用同一 socket），
/// 入方向循环 + 定时器循环在这里跑，解密出的明文包经 channel 交给 TUN 写任务。
pub struct SocketEngine {
    engine: Arc<StdMutex<Engine>>,
    socket: Arc<UdpSocket>,
}

impl SocketEngine {
    /// port 为 0 时由内核分配。实例携带实际绑定地址。
    /// socket 绑定到物理出口网卡（FR-7 共存），默认路由被第三方 TUN 类
    /// 网络工具接管时外层收发仍走物理网卡。
    pub async fn bind(own_secret: StaticSecret, port: u16) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(("0.0.0.0", port))
            .await
            .with_context(|| format!("bind udp 0.0.0.0:{port} failed"))?;
        crate::netif::bind_to_physical_egress(&socket);
        let local_addr = socket
            .local_addr()
            .with_context(|| "query udp local addr failed")?;
        tracing::info!(%local_addr, "wireguard udp socket bound");
        Ok(Self {
            engine: Arc::new(StdMutex::new(Engine::new(own_secret))),
            socket: Arc::new(socket),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .expect("udp socket always has a local addr")
    }

    pub fn reconcile(&self, specs: Vec<PeerSpec>) {
        self.engine
            .lock()
            .expect("engine poisoned")
            .reconcile(specs);
    }

    pub fn handshake_ages(&self) -> HashMap<String, Option<Duration>> {
        self.engine
            .lock()
            .expect("engine poisoned")
            .handshake_ages()
    }

    pub fn peer_count(&self) -> usize {
        self.engine.lock().expect("engine poisoned").peer_count()
    }

    /// TUN 读到的明文 IP 包从这里进引擎。
    pub async fn send_ip_packet(&self, packet: &[u8]) {
        let out = self
            .engine
            .lock()
            .expect("engine poisoned")
            .send_ip_packet(packet);
        send_to_network(&self.socket, out.to_network).await;
    }

    /// 常驻循环：UDP 收包 + 定时器。返回即代表 socket 已不可用；
    /// hzd 停机时直接 abort 本任务。
    pub async fn run(&self, to_tunnel: mpsc::Sender<Vec<u8>>) -> anyhow::Result<()> {
        let ticker = tokio::spawn({
            let engine = self.engine.clone();
            let socket = self.socket.clone();
            let to_tunnel = to_tunnel.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_millis(500));
                loop {
                    interval.tick().await;
                    let out = engine.lock().expect("engine poisoned").tick();
                    forward_to_tunnel(&to_tunnel, out.to_tunnel);
                    send_to_network(&socket, out.to_network).await;
                }
            }
        });

        let mut buf = vec![0u8; MAX_DATAGRAM];
        let result = loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, from)) => {
                    let out = self
                        .engine
                        .lock()
                        .expect("engine poisoned")
                        .handle_udp(from, &buf[..len]);
                    forward_to_tunnel(&to_tunnel, out.to_tunnel);
                    send_to_network(&self.socket, out.to_network).await;
                }
                Err(error) => break Err(anyhow::Error::from(error).context("udp recv failed")),
            }
        };
        ticker.abort();
        result
    }
}

fn forward_to_tunnel(to_tunnel: &mpsc::Sender<Vec<u8>>, packets: Vec<Vec<u8>>) {
    for packet in packets {
        if to_tunnel.try_send(packet).is_err() {
            tracing::warn!("tun write channel full or closed, dropping decrypted packet");
        }
    }
}

/// 按 NetworkSend 的偏好序发送：primary 失败就轮换 alternates。
async fn send_to_network(socket: &Arc<UdpSocket>, sends: Vec<NetworkSend>) {
    for send in sends {
        let mut candidates = std::iter::once(send.primary).chain(send.alternates.iter().copied());
        let mut sent = false;
        for candidate in candidates.by_ref() {
            match socket.send_to(&send.datagram, candidate).await {
                Ok(_) => {
                    sent = true;
                    break;
                }
                Err(error) => tracing::warn!(
                    node_id = %send.node_id,
                    endpoint = %candidate,
                    %error,
                    "udp send failed, rotating endpoint"
                ),
            }
        }
        if !sent {
            tracing::warn!(node_id = %send.node_id, "all endpoints failed for datagram");
        }
    }
}

/// 本机朝 Coordination Server 方向的源 IP + WireGuard 端口，作为上报的 LAN Endpoint。
/// 用临时 UDP socket connect 目标地址，让内核替我们选出路由源地址。
pub async fn lan_endpoint(coord_addr: &str, wg_port: u16) -> anyhow::Result<SocketAddr> {
    let target = coord_probe_target(coord_addr)?;
    let probe = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind probe socket failed")?;
    probe
        .connect(target)
        .await
        .with_context(|| format!("connect probe socket to {target} failed"))?;
    let local = probe
        .local_addr()
        .context("query probe local addr failed")?;
    if local.ip().is_unspecified() {
        bail!("无法确定朝向 {target} 的本机地址");
    }
    Ok(SocketAddr::new(local.ip(), wg_port))
}

/// 解析 Coordination Server 地址（允许带 scheme 与主机名）到探测用 SocketAddr。
/// DNS 解析只在启动时做一次，阻塞可接受。
fn coord_probe_target(coord_addr: &str) -> anyhow::Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    let host_port = coord_addr
        .rsplit_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(coord_addr);
    host_port
        .to_socket_addrs()
        .with_context(|| format!("无法解析 Coordination Server 地址：{coord_addr}"))?
        .next()
        .context(format!(
            "Coordination Server 地址未解析出任何结果：{coord_addr}"
        ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coord_probe_target_strips_scheme_and_accepts_hostnames() {
        assert_eq!(
            coord_probe_target("http://127.0.0.1:443").unwrap(),
            "127.0.0.1:443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            coord_probe_target("127.0.0.1:443").unwrap(),
            "127.0.0.1:443".parse::<SocketAddr>().unwrap()
        );
        assert!(coord_probe_target("no-port-here").is_err());
    }
}
