//! 用户态 WireGuard 引擎（boringtun）。领域结构：PeerTable 以 NodeId 为主键，
//! 每个 Peer 持有一个 noise::Tunn 与传输开关（直连 UDP 或 Relay），加两张派生
//! 索引（目标地址→NodeId、WireGuard 接收索引→NodeId）。UDP socket 由
//! [`SocketEngine`] 持有并独占，与后续打洞（#8）共用；`Engine` 本身不碰网络，
//! 可在任意平台做单元测试。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

use crate::relay_client::RelayClient;
use crate::stun::StunRouter;

/// WireGuard 数据报与 IP 包的统一缓冲上限（UDP 数据报上限 64 KiB）。
const MAX_DATAGRAM: usize = 65536;

/// boringtun 定期保活间隔（秒）。必须小于直连失效判据
/// （[`crate::path::DIRECT_RX_FRESH`]），空闲直连靠保活维持新鲜度。
const KEEPALIVE_SECS: u16 = 8;

/// WireGuard 消息类型字节。
const MSG_HANDSHAKE_INIT: u8 = 1;
const MSG_HANDSHAKE_RESPONSE: u8 = 2;

/// Relay 入站泵单次等待上限：半开旧通道不会自己出错，靠周期回看槽位换新。
const RELAY_PUMP_POLL: Duration = Duration::from_millis(200);

/// 重建 socket 时等常驻任务释放旧 socket 引用的期限与轮询节奏。收发循环
/// 对槽位变化毫秒级响应，1 秒上限只兜极端在途持有者（如 STUN 查询）；
/// 超时后放弃保端口、落到已验证的临时端口 socket，而不是无限等待。
/// 仅 Linux 的重绑路径使用。
#[cfg(target_os = "linux")]
const RECREATE_RELEASE_WAIT: Duration = Duration::from_secs(1);
#[cfg(target_os = "linux")]
const RECREATE_RELEASE_POLL: Duration = Duration::from_millis(5);

/// 入向数据报的接收索引：定位能解密它的本地对端。握手响应的 [4..8] 是
/// 响应方的发送索引，回显给我们的接收索引在 [8..12]；其余消息类型
/// （传输数据、Cookie）的接收索引都在 [4..8]。握手发起包不带索引，
/// 在此之前已逐对端试解归队。
fn inbound_receiver_index(datagram: &[u8]) -> Option<u32> {
    let offset = if datagram.first() == Some(&MSG_HANDSHAKE_RESPONSE) {
        8
    } else {
        4
    };
    datagram
        .get(offset..offset + 4)
        .map(|raw| u32::from_le_bytes(raw.try_into().expect("4 bytes")))
}

/// Network Map 里一个对端的数据面描述。
#[derive(Debug, Clone)]
pub struct PeerSpec {
    pub node_id: String,
    pub node_key_pub: [u8; 32],
    pub endpoints: Vec<SocketAddr>,
    /// 该 Node 的 Node Address（v4 与 ULA v6），本机发往这些地址的包都路由给它。
    pub dst_addrs: Vec<IpAddr>,
    /// 传输开关：true 时发往该对端的 WireGuard 数据报走 Relay（按 node id 寻址），
    /// false 时走直连 UDP。路径选择策略归 #8，当前由调用方（hzd）决定。
    pub use_relay: bool,
}

/// 要发往网络的数据报。primary 失败时按 alternates 顺序重试。
#[derive(Debug, Clone)]
pub struct NetworkSend {
    pub node_id: String,
    pub primary: SocketAddr,
    pub alternates: Vec<SocketAddr>,
    pub datagram: Vec<u8>,
}

/// 要经 Relay 发出的数据报（按 node id 寻址，载荷是 WireGuard 密文）。
#[derive(Debug, Clone)]
pub struct RelaySend {
    pub node_id: String,
    pub datagram: Vec<u8>,
}

/// 一个对端的数据面现状（`hz status` / `hz ping` 的展示来源，FR-12）。
#[derive(Debug, Clone, PartialEq)]
pub struct PeerReport {
    pub node_id: String,
    /// true = 发往该对端走 Relay；false = 直连 UDP。
    pub use_relay: bool,
    /// 当前偏好序第一的 Endpoint（直连时的实际收发地址；Relayed 时不适用）。
    pub endpoint: Option<SocketAddr>,
    /// 最近一次握手距今的时间；None 表示尚未握手。
    pub handshake_age: Option<Duration>,
}

/// 引擎一次处理产生的输出。
#[derive(Debug, Default)]
pub struct EngineOutput {
    pub to_network: Vec<NetworkSend>,
    /// 经 Relay 发往对端的密文数据报。
    pub to_relay: Vec<RelaySend>,
    /// 解密出的明文 IP 包，应写进 TUN。
    pub to_tunnel: Vec<Vec<u8>>,
}

struct Peer {
    node_key_pub: [u8; 32],
    /// 偏好序的 Endpoint 列表，index 0 是当前最佳。
    endpoints: Vec<SocketAddr>,
    tunn: Tunn,
    dst_addrs: Vec<IpAddr>,
    use_relay: bool,
    /// 最近一次从直连 UDP 收到该对端已认证报文的时刻；路径管理据此判直连存活。
    direct_rx: Option<Instant>,
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
            peer.use_relay = spec.use_relay;
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
            // 密钥轮换只意味着会话作废；旧密钥期间学到的直连 Endpoint
            // （对端漫游后的实际地址）仍然可达，作为回退保留进重建后的对端。
            let learned = self
                .peers
                .get(&spec.node_id)
                .map(|peer| peer.endpoints.clone())
                .unwrap_or_default();
            let old = self.peers.insert(
                spec.node_id.clone(),
                Peer {
                    node_key_pub: spec.node_key_pub,
                    endpoints: merge_endpoints(learned, spec.endpoints),
                    tunn,
                    dst_addrs: spec.dst_addrs,
                    use_relay: spec.use_relay,
                    direct_rx: None,
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

    /// 本机 Node Key 轮换（重新登录，FR-3）：替换静态私钥并清空全部对端。
    /// 旧私钥建立的会话不允许在新密钥下续命；对端由随后的 reconcile 重建。
    pub fn rotate_own_key(&mut self, secret: StaticSecret) {
        self.own_secret = secret;
        let stale: Vec<String> = self.peers.keys().cloned().collect();
        for id in stale {
            self.remove_peer(&id);
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
            self.dispatch_network(&node_id, datagram, &mut out);
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
            self.note_direct_rx(&node_id);
            self.register_own_index(&node_id, &response);
            out.to_network.push(NetworkSend {
                node_id,
                primary: from,
                alternates: Vec::new(),
                datagram: response,
            });
            return out;
        }

        let Some(node_id) =
            inbound_receiver_index(datagram).and_then(|index| self.by_index.get(&index).cloned())
        else {
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
        if !matches!(result, TunnResult::Err(_)) {
            self.note_direct_rx(&node_id);
        }
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

    /// Relay 入方向的一个 WireGuard 数据报。Relay 按流的归属投递（流在认证时
    /// 已绑定 node id），没有 UDP 那样的源端点：不传源地址（boringtun 不做
    /// 端点漫游），回包按对端传输开关经 Relay 发回。
    pub fn handle_relay_datagram(&mut self, datagram: &[u8]) -> EngineOutput {
        let mut out = EngineOutput::default();
        let Some(&msg_type) = datagram.first() else {
            return out;
        };
        let mut scratch = vec![0u8; MAX_DATAGRAM];

        if msg_type == MSG_HANDSHAKE_INIT {
            let mut found = None;
            for candidate in self.peers.keys().cloned().collect::<Vec<_>>() {
                let result = self
                    .peers
                    .get_mut(&candidate)
                    .expect("iterating live peers")
                    .tunn
                    .decapsulate(None, datagram, &mut scratch);
                if let TunnResult::WriteToNetwork(bytes) = result {
                    found = Some((candidate, bytes.to_vec()));
                    break;
                }
            }
            let Some((node_id, response)) = found else {
                tracing::debug!("drop relayed handshake initiation from unknown peer");
                return out;
            };
            self.register_own_index(&node_id, &response);
            self.dispatch_network(&node_id, response, &mut out);
            return out;
        }

        let Some(node_id) =
            inbound_receiver_index(datagram).and_then(|index| self.by_index.get(&index).cloned())
        else {
            tracing::debug!(%msg_type, "drop relayed wireguard datagram for unknown index");
            return out;
        };
        let result = self
            .peers
            .get_mut(&node_id)
            .expect("by_index 与 peers 一致")
            .tunn
            .decapsulate(None, datagram, &mut scratch);
        let mut pending = Some(step_result(result));
        while let Some(step) = pending.take() {
            match step {
                Step::Network(datagram) => {
                    self.register_own_index(&node_id, &datagram);
                    self.dispatch_network(&node_id, datagram, &mut out);
                }
                Step::Tunnel(packet) => out.to_tunnel.push(packet),
                Step::Stop => break,
            }
            let next = self
                .peers
                .get_mut(&node_id)
                .expect("by_index 与 peers 一致")
                .tunn
                .decapsulate(None, &[], &mut scratch);
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
                self.dispatch_network(&node_id, datagram, &mut out);
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

    /// 各对端的数据面现状（路径、在用 Endpoint、最近握手），供状态展示。
    /// Relayed 时没有在用的对端 Endpoint（收发都经 Relay 按 node id 寻址）。
    pub fn peer_reports(&self) -> Vec<PeerReport> {
        self.peers
            .iter()
            .map(|(id, peer)| PeerReport {
                node_id: id.clone(),
                use_relay: peer.use_relay,
                endpoint: if peer.use_relay {
                    None
                } else {
                    peer.endpoints.first().copied()
                },
                handshake_age: peer.tunn.time_since_last_handshake(),
            })
            .collect()
    }

    /// 各对端最近一次直连接收距今的时间；None 表示从未直连收到。
    /// 路径管理（#8）据此判断 Direct Path 存活。
    pub fn direct_rx_ages(&self) -> HashMap<String, Option<Duration>> {
        self.peers
            .iter()
            .map(|(id, peer)| (id.clone(), peer.direct_rx.map(|at| at.elapsed())))
            .collect()
    }

    /// 生成一个握手发起包（打洞包）：从共享 socket 发往对端候选，
    /// 同时打开双方 NAT 映射。不强制重发——进行中的握手（例如 Relay 侧正在
    /// 完成的那个）不能被反复重置，否则对称 NAT 场景下 Relay 会话永远建立
    /// 不起来。对端不在册、或握手进行中返回 None。
    pub fn punch_handshake(&mut self, node_id: &str) -> Option<Vec<u8>> {
        let mut scratch = vec![0u8; MAX_DATAGRAM];
        let datagram = {
            let peer = self.peers.get_mut(node_id)?;
            match peer.tunn.format_handshake_initiation(&mut scratch, false) {
                TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
                _ => return None,
            }
        };
        self.register_own_index(node_id, &datagram);
        Some(datagram)
    }

    /// 调整该对端的传输开关（true = Relay）。对端不在册时忽略。
    pub fn set_use_relay(&mut self, node_id: &str, use_relay: bool) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.use_relay = use_relay;
        }
    }

    /// 作废全部对端的直连接收记账（网络变化恢复用）：下一次路径推进会把
    /// 在用 Direct Path 判为失效、退回 Relay 并重启打洞。只清新鲜度，
    /// 对端密钥与候选 Endpoint（对端没动时仍然有效）一概保留。
    pub fn reset_direct_rx(&mut self) {
        for peer in self.peers.values_mut() {
            peer.direct_rx = None;
        }
    }

    /// 追加候选 Endpoint（打洞信令带来的对端实时地址），去重、不扰动偏好序。
    pub fn add_peer_endpoints(&mut self, node_id: &str, candidates: Vec<SocketAddr>) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            for addr in candidates {
                if !peer.endpoints.contains(&addr) {
                    peer.endpoints.push(addr);
                }
            }
        }
    }

    fn note_direct_rx(&mut self, node_id: &str) {
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.direct_rx = Some(Instant::now());
        }
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

    /// 按对端当前传输开关出向分发：Relay（按 node id）或直连 UDP。
    fn dispatch_network(&self, node_id: &str, datagram: Vec<u8>, out: &mut EngineOutput) {
        let uses_relay = self.peers.get(node_id).is_some_and(|peer| peer.use_relay);
        if uses_relay {
            out.to_relay.push(RelaySend {
                node_id: node_id.to_owned(),
                datagram,
            });
        } else if let Some(send) = self.network_send(node_id, datagram) {
            out.to_network.push(send);
        }
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

/// 合并 Endpoint：新地址提到最前（保持 fresh 自身顺序），已有地址去重，保持偏好序。
fn merge_endpoints(mut preferred: Vec<SocketAddr>, fresh: Vec<SocketAddr>) -> Vec<SocketAddr> {
    for addr in fresh.into_iter().rev() {
        preferred.retain(|existing| *existing != addr);
        preferred.insert(0, addr);
    }
    preferred
}

/// 持有唯一 UDP socket 的引擎外壳：socket 归它所有（#8 打洞复用同一 socket），
/// 入方向循环 + 定时器循环在这里跑，解密出的明文包经 channel 交给 TUN 写任务。
/// 设置了 Relay 客户端（[`SocketEngine::set_relay`]）时，开关指向 Relay 的对端
/// 走 TLS 中继收发，直连 UDP 路径不变。Relay 客户端可随时替换（断线重连），
/// 新的入站流会被自动接管。
///
/// socket 存放在 watch 槽位里：网络变化重绑（[`SocketEngine::rebind`]）需要
/// 重建 socket 时原子换入新值，常驻循环（收包、定时器）在每次收发前取当前
/// socket，换入后自动跟上，持有旧 socket 的等待随即作废。
pub struct SocketEngine {
    engine: Arc<StdMutex<Engine>>,
    socket_tx: watch::Sender<Arc<UdpSocket>>,
    /// 当前 SO_BINDTODEVICE 目标（内核不提供回读，自行记账用于幂等重绑）。
    /// macOS 侧只写不读（rebind 随 #16 接入），先豁免死代码告警。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    device: StdMutex<Option<String>>,
    /// 测试钩子（#[doc(hidden)] 方法置位）：让下一次 rebind 的在位改绑
    /// 按失败处理，确定性走重建路径；仅 Linux 分支读取。
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fail_live_reapply: StdMutex<bool>,
    relay: Arc<StdMutex<Option<Arc<RelayClient>>>>,
    stun_router: Arc<StunRouter>,
    punch_in: Arc<StdMutex<Option<mpsc::Sender<Vec<u8>>>>>,
}

/// 一次重绑的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebindOutcome {
    /// 绑定目标未变（幂等重入），socket 原样保留。
    Kept,
    /// 现有 socket 重新应用了 SO_BINDTODEVICE，端口不变。
    Rebound,
    /// 现有 socket 无法改绑，已重建并原子换入。重建保端口；仅当原端口
    /// 在腾出后的窗口被抢占等极限情形才落到新端口。
    Recreated { port: u16 },
}

impl SocketEngine {
    /// port 为 0 时由内核分配。实例携带实际绑定地址。
    /// socket 优先按 IPv6 双栈绑定（v4-mapped 兼容 v4，IPv6 Direct Path 需要
    /// 同一 socket 收发两个族），内核不支持时退回纯 v4。
    /// socket 绑定到物理出口网卡（FR-7 共存），默认路由被第三方 TUN 类
    /// 网络工具接管时外层收发仍走物理网卡。
    pub async fn bind(own_secret: StaticSecret, port: u16) -> anyhow::Result<Self> {
        Self::bind_with(own_secret, port, true).await
    }

    /// [`SocketEngine::bind`] 的出口绑定开关版。bind_to_egress=false 时
    /// socket 不绑物理出口网卡：回环测试拓扑与本地开发的对端无法从物理
    /// 网卡到达（SO_BINDTODEVICE 会挡掉 127.0.0.1 收发）；生产路径必须
    /// 保持 true（FR-7 与第三方 TUN 类网络工具共存）。
    pub async fn bind_with(
        own_secret: StaticSecret,
        port: u16,
        bind_to_egress: bool,
    ) -> anyhow::Result<Self> {
        let socket = bind_dual_stack(port)
            .await
            .with_context(|| format!("bind udp :{port} failed"))?;
        let device = if bind_to_egress {
            crate::netif::bind_to_physical_egress(&socket)
        } else {
            None
        };
        let local_addr = socket
            .local_addr()
            .with_context(|| "query udp local addr failed")?;
        tracing::info!(%local_addr, ?device, "wireguard udp socket bound");
        Ok(Self {
            engine: Arc::new(StdMutex::new(Engine::new(own_secret))),
            socket_tx: watch::Sender::new(Arc::new(socket)),
            device: StdMutex::new(device),
            fail_live_reapply: StdMutex::new(false),
            relay: Arc::new(StdMutex::new(None)),
            stun_router: Arc::new(StunRouter::default()),
            punch_in: Arc::new(StdMutex::new(None)),
        })
    }

    /// 当前 socket（重建换入后的最新值）。
    fn socket(&self) -> Arc<UdpSocket> {
        self.socket_tx.borrow().clone()
    }

    /// 网络变化后的重绑（FR-7 物理出口变化随之重绑）：目标是把唯一的 UDP
    /// socket 挪到新的物理出口网卡上，对端密钥与候选一概不动。
    /// 绑定目标未变时是幂等空操作；变了就先对现有 socket 重新应用
    /// SO_BINDTODEVICE（socket 绑的是通配地址，网卡换了名子绑定仍合法，
    /// 端口得以保留）。在位改绑失败有两类情形：目标网卡瞬时消失（换
    /// Wi-Fi、驱动重绑、网卡重命名的窗口期）时以 ENODEV 拒绝；以及内核
    /// 对"改绑已绑设备的 socket"要求 CAP_NET_RAW（仅首次绑定免特权，
    /// net/core/sock.c 按 sk_bound_dev_if 判定）——无特权进程的重绑必然
    /// 走重建。重建必须保端口（对端学到的 Endpoint 才不失效）：旧 socket
    /// 在位时同端口重绑必 EADDRINUSE（UDP 无 SO_REUSEPORT），所以先把旧
    /// socket 换出槽位、等常驻任务放手后关闭，再按原端口重绑新 socket
    /// 并原子换入；换出与换入之间端口短暂无人监听，这个丢包窗口是重绑
    /// 事件的固有代价。
    /// 重建后旧 socket 上的等待中的 STUN 事务靠自身 3 秒超时自然清理，
    /// 新查询自动走新 socket，无需显式通知 StunRouter。
    pub async fn rebind(&self, egress: &str) -> anyhow::Result<RebindOutcome> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = egress;
            anyhow::bail!(
                "socket 重绑目前仅 Linux 实现（SO_BINDTODEVICE）；macOS 的 IP_BOUND_IF 随 #16 接入"
            );
        }
        #[cfg(target_os = "linux")]
        {
            if *self.device.lock().expect("device poisoned") == Some(egress.to_string()) {
                return Ok(RebindOutcome::Kept);
            }
            let socket = self.socket();
            // 钩子置位时在位改绑按失败处理：模拟无 CAP_NET_RAW 内核上的
            // EPERM，让重建路径可在特权环境里被确定性测到。
            let forced_fail = std::mem::replace(
                &mut *self.fail_live_reapply.lock().expect("test hook poisoned"),
                false,
            );
            let reapplied = if forced_fail {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "forced by test hook",
                ))
            } else {
                socket2::SockRef::from(socket.as_ref()).bind_device(Some(egress.as_bytes()))
            };
            match reapplied {
                Ok(()) => {
                    *self.device.lock().expect("device poisoned") = Some(egress.to_string());
                    tracing::info!(%egress, "udp socket rebound to physical egress");
                    Ok(RebindOutcome::Rebound)
                }
                Err(error) => {
                    tracing::warn!(%egress, %error, "rebind device on live socket failed, recreating");
                    let port = socket.local_addr()?.port();
                    // 先在临时端口的新 socket 上验证 egress 可绑（首次绑设备
                    // 无需特权）。失败说明 egress 本身不可用（如网卡已消失），
                    // 旧 socket 原样在位，显式报错且端口不动。
                    let fallback = Arc::new(bind_dual_stack(0).await.with_context(|| {
                        format!("recreate udp socket for egress {egress} failed")
                    })?);
                    socket2::SockRef::from(fallback.as_ref())
                        .bind_device(Some(egress.as_bytes()))
                        .with_context(|| format!("bind recreated socket to {egress} failed"))?;
                    // 换入临时 socket 让常驻循环放手旧 socket；引用清零后
                    // 关闭旧 fd 腾出端口，同端口重绑才可能成功。
                    self.socket_tx.send_modify(|slot| *slot = fallback.clone());
                    let deadline = tokio::time::Instant::now() + RECREATE_RELEASE_WAIT;
                    while Arc::strong_count(&socket) > 1 && tokio::time::Instant::now() < deadline {
                        tokio::time::sleep(RECREATE_RELEASE_POLL).await;
                    }
                    drop(socket);
                    let fresh = match bind_dual_stack(port).await {
                        Ok(fresh) => {
                            // egress 刚在临时 socket 上验证过；同端口新 socket
                            // 仍是首次绑设备，再失败只剩设备在窗口内消失的
                            // 竞态，退回已验证的临时 socket。
                            if let Err(error) =
                                socket2::SockRef::from(&fresh).bind_device(Some(egress.as_bytes()))
                            {
                                tracing::warn!(%egress, %error, "bind same-port socket to device failed, keeping validated fallback");
                                fallback
                            } else {
                                Arc::new(fresh)
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "recreate on same port failed, keeping validated fallback");
                            fallback
                        }
                    };
                    let fresh_port = fresh
                        .local_addr()
                        .with_context(|| "query recreated udp local addr failed")?
                        .port();
                    self.socket_tx.send_modify(|slot| *slot = fresh);
                    *self.device.lock().expect("device poisoned") = Some(egress.to_string());
                    tracing::info!(%egress, port = fresh_port, "udp socket recreated for new egress");
                    Ok(RebindOutcome::Recreated { port: fresh_port })
                }
            }
        }
    }

    /// 测试钩子：强制下一次 [`SocketEngine::rebind`] 走重建路径（在位改绑
    /// 按失败处理）。模拟无 CAP_NET_RAW 的内核只放行首次设备绑定的行为；
    /// 生产代码不得调用。
    #[doc(hidden)]
    pub fn fail_live_reapply_for_test(&self) {
        *self.fail_live_reapply.lock().expect("test hook poisoned") = true;
    }

    /// 接入 Relay 传输。断线重连由装配层的监督任务再次调用本方法完成；
    /// 替换后引擎自动接管新客户端的入站流。
    pub fn set_relay(&self, client: Arc<RelayClient>) {
        *self.relay.lock().expect("relay poisoned") = Some(client);
    }

    /// 当前 Relay 客户端（可能未接入）。打洞信令经它发给对端。
    pub fn relay_client(&self) -> Option<Arc<RelayClient>> {
        self.relay.lock().expect("relay poisoned").clone()
    }

    /// 登记打洞信令的入站队列：Relay 数据报带打洞前缀时原样投递到这里，
    /// 由装配层（hzd 的路径任务）解密处理。只能设置一次。
    pub fn set_punch_handler(&self, inbound: mpsc::Sender<Vec<u8>>) {
        *self.punch_in.lock().expect("punch handler poisoned") = Some(inbound);
    }

    /// 从共享 socket 发起 STUN 查询（FR-8）：响应经收包循环按事务 id 路由
    /// 回调用方，不与引擎抢收。返回的即本 socket 的公网映射 Endpoint。
    pub async fn stun_query(&self, server: SocketAddr) -> anyhow::Result<SocketAddr> {
        self.stun_router.query(&self.socket(), server).await
    }

    /// 朝对端全部候选 Endpoint 发一个握手发起包（打洞）。v6 候选在最前，
    /// 逐个尝试；单个候选发送失败只记录。
    pub async fn send_punch(&self, node_id: &str) {
        let punch = {
            let mut engine = self.engine.lock().expect("engine poisoned");
            engine
                .punch_handshake(node_id)
                .map(|datagram| (datagram, engine.endpoint_candidates(node_id)))
        };
        let Some((datagram, candidates)) = punch else {
            return;
        };
        if candidates.is_empty() {
            tracing::debug!(node_id, "punch without any candidate endpoint");
        }
        let socket = self.socket();
        for candidate in candidates {
            if let Err(error) = socket.send_to(&datagram, candidate).await {
                tracing::debug!(node_id, endpoint = %candidate, %error, "punch send failed");
            }
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.socket()
            .local_addr()
            .expect("udp socket always has a local addr")
    }

    pub fn reconcile(&self, specs: Vec<PeerSpec>) {
        self.engine
            .lock()
            .expect("engine poisoned")
            .reconcile(specs);
    }

    /// 重新登录后的本机 Node Key 轮换：换私钥、清对端，调用方随后重放
    /// Network Map 对账以重建会话。
    pub fn rotate_own_key(&self, secret: StaticSecret) {
        self.engine
            .lock()
            .expect("engine poisoned")
            .rotate_own_key(secret);
    }

    pub fn handshake_ages(&self) -> HashMap<String, Option<Duration>> {
        self.engine
            .lock()
            .expect("engine poisoned")
            .handshake_ages()
    }

    /// 各对端的数据面现状（路径、在用 Endpoint、最近握手）。
    pub fn peer_reports(&self) -> Vec<PeerReport> {
        self.engine.lock().expect("engine poisoned").peer_reports()
    }

    pub fn direct_rx_ages(&self) -> HashMap<String, Option<Duration>> {
        self.engine
            .lock()
            .expect("engine poisoned")
            .direct_rx_ages()
    }

    /// 偏好序的 Endpoint 候选（路径日志与打洞发送用）。
    pub fn endpoint_candidates(&self, node_id: &str) -> Vec<SocketAddr> {
        self.engine
            .lock()
            .expect("engine poisoned")
            .endpoint_candidates(node_id)
    }

    /// 调整对端传输开关（true = Relay）。
    pub fn set_use_relay(&self, node_id: &str, use_relay: bool) {
        self.engine
            .lock()
            .expect("engine poisoned")
            .set_use_relay(node_id, use_relay);
    }

    /// 把某个地址提升为该对端的最佳 Endpoint（IPv6 直连优先的落点：
    /// 升级 Direct 时把发送偏好切到 v6 候选）。
    pub fn prefer_endpoint(&self, node_id: &str, addr: SocketAddr) {
        self.engine
            .lock()
            .expect("engine poisoned")
            .prefer_endpoint(node_id, addr);
    }

    /// 追加对端候选 Endpoint（打洞信令带来的实时地址）。
    pub fn add_peer_endpoints(&self, node_id: &str, candidates: Vec<SocketAddr>) {
        self.engine
            .lock()
            .expect("engine poisoned")
            .add_peer_endpoints(node_id, candidates);
    }

    pub fn peer_count(&self) -> usize {
        self.engine.lock().expect("engine poisoned").peer_count()
    }

    /// 作废全部对端的直连接收记账（网络变化恢复用）；等价语义见
    /// [`Engine::reset_direct_rx`]。
    pub fn reset_direct_rx(&self) {
        self.engine
            .lock()
            .expect("engine poisoned")
            .reset_direct_rx();
    }

    /// TUN 读到的明文 IP 包从这里进引擎。
    pub async fn send_ip_packet(&self, packet: &[u8]) {
        let out = {
            let mut engine = self.engine.lock().expect("engine poisoned");
            engine.send_ip_packet(packet)
        };
        let socket = self.socket();
        send_to_network(&socket, out.to_network).await;
        send_to_relay(&self.relay, out.to_relay).await;
    }

    /// 常驻循环：UDP 收包 + 定时器 + （若接入）Relay 收包。
    /// 收包循环每次迭代取槽位里的当前 socket，并在槽位变化（重绑重建）时
    /// 立即切换，旧 socket 上的等待随本迭代取消。
    /// 返回即代表 socket 已不可用；hzd 停机时直接 abort 本任务。
    pub async fn run(&self, to_tunnel: mpsc::Sender<Vec<u8>>) -> anyhow::Result<()> {
        let ticker = tokio::spawn({
            let engine = self.engine.clone();
            let socket_tx = self.socket_tx.clone();
            let relay_slot = self.relay.clone();
            let to_tunnel = to_tunnel.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_millis(500));
                loop {
                    interval.tick().await;
                    let out = engine.lock().expect("engine poisoned").tick();
                    forward_to_tunnel(&to_tunnel, out.to_tunnel);
                    let socket = socket_tx.borrow().clone();
                    send_to_network(&socket, out.to_network).await;
                    send_to_relay(&relay_slot, out.to_relay).await;
                }
            }
        });

        // Relay 入站泵：监听 relay 槽位，断线重连/出口强拔换上新客户端后接管
        // 新流。消费节奏带 200ms 上限：泵可能停在旧客户端的入站通道上等帧，
        // 而旧通道对应的 TCP 已是半开（出口切换后对端不可达），要等 h2
        // keepalive 超时（秒级）才关闭——不等它，周期性比对槽位里的客户端
        // 是否已被替换，替换即刻切换，新通道上排队的帧才不会被扣住。
        // WireGuard 密文进引擎；带打洞前缀的帧原样交给装配层的信令队列。
        tokio::spawn({
            let engine = self.engine.clone();
            let relay_slot = self.relay.clone();
            let punch_in = self.punch_in.clone();
            let to_tunnel = to_tunnel.clone();
            async move {
                loop {
                    let current = relay_slot.lock().expect("relay poisoned").clone();
                    if let Some(relay) = current {
                        if let Some(mut incoming) = relay.take_incoming() {
                            loop {
                                let next =
                                    tokio::time::timeout(RELAY_PUMP_POLL, incoming.recv()).await;
                                let datagram = match next {
                                    Ok(Some(datagram)) => datagram,
                                    Ok(None) => break,
                                    Err(_elapsed) => {
                                        let installed =
                                            relay_slot.lock().expect("relay poisoned").clone();
                                        match installed {
                                            Some(latest) if Arc::ptr_eq(&latest, &relay) => {
                                                continue;
                                            }
                                            _ => break,
                                        }
                                    }
                                };
                                if route_punch_signal(&punch_in, &datagram) {
                                    continue;
                                }
                                let out = {
                                    let mut engine = engine.lock().expect("engine poisoned");
                                    engine.handle_relay_datagram(&datagram)
                                };
                                forward_to_tunnel(&to_tunnel, out.to_tunnel);
                                send_to_relay(&relay_slot, out.to_relay).await;
                            }
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        });

        let mut socket_rx = self.socket_tx.subscribe();
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let result = loop {
            let socket = socket_rx.borrow_and_update().clone();
            tokio::select! {
                changed = socket_rx.changed() => {
                    if changed.is_err() {
                        break Err(anyhow::anyhow!("socket slot closed"));
                    }
                    continue;
                }
                received = socket.recv_from(&mut buf) => {
                    match received {
                        Ok((len, from)) => {
                            let datagram = &buf[..len];
                            // STUN 响应按事务 id 路由回等待中的查询，不进 WireGuard。
                            if self.stun_router.dispatch(datagram) {
                                continue;
                            }
                            let out = {
                                let mut engine = self.engine.lock().expect("engine poisoned");
                                engine.handle_udp(from, datagram)
                            };
                            forward_to_tunnel(&to_tunnel, out.to_tunnel);
                            let socket = self.socket();
                            send_to_network(&socket, out.to_network).await;
                            send_to_relay(&self.relay, out.to_relay).await;
                        }
                        Err(error) => {
                            break Err(anyhow::Error::from(error).context("udp recv failed"))
                        }
                    }
                }
            }
        };
        ticker.abort();
        result
    }
}

/// 单 socket 双栈绑定：先试 [::] 关闭 v6only（v4-mapped 收 v4），失败再退
/// 纯 v4。打洞与 WireGuard 共用这一个 socket（ADR-0002），IPv6 直连也必须
/// 落在它上面。
async fn bind_dual_stack(port: u16) -> anyhow::Result<UdpSocket> {
    match socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(v6) => {
            if let Err(error) = v6.set_only_v6(false) {
                tracing::warn!(%error, "disable IPV6_V6ONLY failed, falling back to v4");
            } else {
                v6.set_nonblocking(true)?;
                let addr: std::net::SocketAddr =
                    format!("[::]:{port}").parse().expect("valid socket addr");
                if v6.bind(&socket2::SockAddr::from(addr)).is_ok() {
                    return Ok(UdpSocket::from_std(v6.into())?);
                }
                tracing::warn!("bind [::]:{port} failed, falling back to v4 only");
            }
        }
        Err(error) => {
            tracing::warn!(%error, "ipv6 socket unavailable, falling back to v4 only");
        }
    }
    Ok(UdpSocket::bind(("0.0.0.0", port)).await?)
}

fn forward_to_tunnel(to_tunnel: &mpsc::Sender<Vec<u8>>, packets: Vec<Vec<u8>>) {
    for packet in packets {
        if to_tunnel.try_send(packet).is_err() {
            tracing::warn!("tun write channel full or closed, dropping decrypted packet");
        }
    }
}

/// 打洞信令帧的入站分流：是信令就投递给装配层并返回 true（引擎不处理）。
fn route_punch_signal(
    punch_in: &Arc<StdMutex<Option<mpsc::Sender<Vec<u8>>>>>,
    datagram: &[u8],
) -> bool {
    if !crate::punch::is_punch(datagram) {
        return false;
    }
    let slot = punch_in.lock().expect("punch handler poisoned");
    match slot.as_ref() {
        Some(sender) => {
            if sender.try_send(datagram.to_vec()).is_err() {
                tracing::warn!("punch signal queue full or closed, dropping");
            }
            true
        }
        None => {
            tracing::debug!("punch signal received before handler registered, dropping");
            true
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

/// 把 Relay 侧出向数据报交给中继客户端（未接入中继时丢弃并告警）。
async fn send_to_relay(relay: &StdMutex<Option<Arc<RelayClient>>>, sends: Vec<RelaySend>) {
    if sends.is_empty() {
        return;
    }
    let Some(relay) = relay.lock().expect("relay poisoned").clone() else {
        tracing::warn!(
            count = sends.len(),
            "relay datagrams produced without a relay client, dropping"
        );
        return;
    };
    for send in sends {
        relay.send_datagram(&send.node_id, send.datagram).await;
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
