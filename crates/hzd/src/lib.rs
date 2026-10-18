//! hzd 守护进程主体：状态目录、密钥、UDS 服务、注册与数据面。
//! 数据面 = 一个 [`SocketEngine`]（WireGuard over UDP）+ hz0 TUN + Network Map 订阅；
//! TUN 不可用时降级为纯控制面（注册与状态照常），方便无 root 环境跑测试。
//! main 只负责 tracing 初始化与 Ctrl-C；守护化（systemd/launchd 托管）不在本进程内做。
//! 注册结果持久化在状态目录的 registration.json（0600），重启后仍是 Registered。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use hz_core::coord_client::{
    DEFAULT_COORD_ADDR, LoginPoll, StartedLogin, begin_interactive_login, local_hostname,
    open_network_map_stream, poll_login_status, register_with_auth_key, report_endpoints,
};
use hz_core::endpoint::{self, DiscoveredEndpoint};
use hz_core::ipc::{self, Handler};
use hz_core::keys::KeyStore;
use hz_core::map::{MapNode, NetworkMapCache};
use hz_core::path::{PathEvent, PathManager, PeerEndpoints};
use hz_core::punch::{PunchCodec, PunchMessage};
use hz_core::status::{NodeStatus, RegisteredInfo};
#[cfg(target_os = "linux")]
use hz_core::tun::{DEFAULT_V4_CIDR, Tun, TunConfig};
use hz_core::wire::{PeerSpec, SocketEngine, lan_endpoint};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

const REGISTRATION_FILE: &str = "registration.json";

/// 断线重连退避：1s 起步、翻倍、30s 封顶（叠加亚秒抖动）。
const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Endpoint 收集与上报周期（FR-8）。
const ENDPOINT_COLLECT_EVERY: Duration = Duration::from_secs(30);

/// 一次交互式登录在 hzd 内的进度；终态只保留最后一次，重复 up 覆盖。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum LoginProgress {
    Idle,
    Pending,
    Completed,
    Failed { error: String },
}

/// `hz status` 展示的一个对端；来源于本地 Network Map 缓存。
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MapPeer {
    pub name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub endpoints: Vec<String>,
    pub handshake_secs: Option<u64>,
}

struct Daemon {
    state_dir: PathBuf,
    registration: StdMutex<Option<RegisteredInfo>>,
    map_cache: Arc<NetworkMapCache>,
    engine: StdMutex<Option<Arc<SocketEngine>>>,
    /// 最近一次成功使用的 Coordination Server 地址；重启后自动重连用它。
    coord_addr: StdMutex<Option<String>>,
    login: StdMutex<LoginProgress>,
    /// Network Map 有变化时唤醒路径任务（打洞轮次紧跟对端 Endpoint 更新）。
    map_signal: Arc<tokio::sync::Notify>,
    /// 最近一次收集到的本机 Endpoint（PunchOffer 的候选来源）。
    own_endpoints: Arc<StdMutex<Vec<DiscoveredEndpoint>>>,
    /// 路径管理的当前决定（node_id → 走 Relay）；对账数据面时保序用。
    use_relay: Arc<StdMutex<HashMap<String, bool>>>,
}

pub async fn run(state_dir: PathBuf, socket_path: PathBuf) -> anyhow::Result<()> {
    let keys = Arc::new(KeyStore::load_or_create(&state_dir)?);
    tracing::info!(
        machine_public = %hex(&keys.machine_public()),
        node_public = %hex(&keys.node_public()),
        "keys ready"
    );
    let registration = load_registration(&state_dir)?;
    if registration.is_some() {
        tracing::info!("loaded existing registration from disk");
    }
    let map_cache = match NetworkMapCache::load(&state_dir) {
        Ok(cache) => Arc::new(cache),
        Err(error) => {
            // 缓存损坏不该卡死守护进程：清空重来，Coordination Server 在线时很快补齐。
            tracing::error!(%error, "load network map cache failed, starting empty");
            Arc::new(NetworkMapCache::empty(&state_dir))
        }
    };
    let daemon = Arc::new(Daemon {
        state_dir,
        registration: StdMutex::new(registration.as_ref().map(|file| file.info.clone())),
        map_cache,
        engine: StdMutex::new(None),
        coord_addr: StdMutex::new(
            registration
                .and_then(|file| file.coord_addr)
                .filter(|addr| !addr.is_empty()),
        ),
        login: StdMutex::new(LoginProgress::Idle),
        map_signal: Arc::new(tokio::sync::Notify::new()),
        own_endpoints: Arc::new(StdMutex::new(Vec::new())),
        use_relay: Arc::new(StdMutex::new(HashMap::new())),
    });

    // 开机即已注册：直接拉起数据面；coord 地址取注册时记下的，其次环境变量。
    let boot_info = daemon
        .registration
        .lock()
        .expect("registration poisoned")
        .clone();
    if let Some(info) = boot_info {
        let coord_addr = daemon
            .coord_addr
            .lock()
            .expect("coord addr poisoned")
            .clone()
            .unwrap_or_else(|| std::env::var("HZD_COORD_ADDR").unwrap_or_default());
        let coord_addr = if coord_addr.is_empty() {
            DEFAULT_COORD_ADDR.to_string()
        } else {
            coord_addr
        };
        if let Err(error) = start_dataplane(&daemon, &keys, &info, &coord_addr).await {
            tracing::error!(%error, "dataplane startup failed at boot");
        }
    }

    let handler: Handler = {
        let daemon = daemon.clone();
        let keys = keys.clone();
        Arc::new(move |request: ipc::Request| {
            let daemon = daemon.clone();
            let keys = keys.clone();
            Box::pin(handle_request(request, daemon, keys))
        })
    };
    ipc::serve(&socket_path, handler).await
}

async fn handle_request(
    request: ipc::Request,
    daemon: Arc<Daemon>,
    keys: Arc<KeyStore>,
) -> Result<Value, String> {
    match request.method.as_str() {
        "status" => {
            let registration = daemon
                .registration
                .lock()
                .expect("registration poisoned")
                .clone();
            let status = match registration {
                Some(info) => NodeStatus::Registered(info),
                None => {
                    return serde_json::to_value(NodeStatus::Unregistered)
                        .map_err(|e| e.to_string());
                }
            };
            let mut value = serde_json::to_value(status).map_err(|e| e.to_string())?;
            value["peers"] =
                serde_json::to_value(peers_view(&daemon)).map_err(|e| e.to_string())?;
            Ok(value)
        }
        "up" => {
            let coord_addr = request
                .params
                .get("coord_addr")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .or_else(|| std::env::var("HZD_COORD_ADDR").ok())
                .unwrap_or_else(|| DEFAULT_COORD_ADDR.to_string());

            match request.params.get("auth_key").and_then(|v| v.as_str()) {
                Some(auth_key) => {
                    let info = register_with_auth_key(
                        &daemon.state_dir,
                        auth_key,
                        &local_hostname(),
                        &coord_addr,
                    )
                    .await
                    .map_err(|error| format!("{error:#}"))?;
                    finish_registration(&daemon, &keys, info, &coord_addr)
                        .await
                        .map_err(|error| format!("{error:#}"))
                }
                None => {
                    // 无 Auth Key：交互式登录（FR-2）。申请到一次性链接立刻返回给
                    // CLI 打印，轮询在后台任务里继续。
                    let started =
                        begin_interactive_login(&daemon.state_dir, &local_hostname(), &coord_addr)
                            .await
                            .map_err(|error| format!("{error:#}"))?;
                    *daemon.login.lock().expect("login poisoned") = LoginProgress::Pending;
                    let login_url = started.login_url.clone();
                    let expires_unix = started.expires_unix;
                    spawn_login_poller(daemon.clone(), keys.clone(), started, coord_addr);
                    Ok(serde_json::json!({
                        "login_url": login_url,
                        "expires_unix": expires_unix,
                    }))
                }
            }
        }
        "login_poll" => {
            let progress = daemon.login.lock().expect("login poisoned").clone();
            let registration = daemon
                .registration
                .lock()
                .expect("registration poisoned")
                .clone();
            let value = serde_json::to_value(&progress).map_err(|e| e.to_string())?;
            match (&progress, registration) {
                (LoginProgress::Completed, Some(info)) => {
                    let mut value = value;
                    value["node"] = serde_json::to_value(&info).map_err(|e| e.to_string())?;
                    Ok(value)
                }
                _ => Ok(value),
            }
        }
        _ => Err(format!("unknown method: {}", request.method)),
    }
}

/// 注册/登录完成后共用的落盘与数据面拉起。
async fn finish_registration(
    daemon: &Arc<Daemon>,
    keys: &Arc<KeyStore>,
    info: RegisteredInfo,
    coord_addr: &str,
) -> Result<Value, String> {
    save_registration(&daemon.state_dir, &info, coord_addr)
        .map_err(|error| format!("{error:#}"))?;
    *daemon.registration.lock().expect("registration poisoned") = Some(info.clone());
    *daemon.coord_addr.lock().expect("coord addr poisoned") = Some(coord_addr.to_string());
    tracing::info!(node_id = %info.node_id, name = %info.name, "node registered");
    if let Err(error) = start_dataplane(daemon, keys, &info, coord_addr).await {
        // 数据面失败不回滚注册：控制面可用，问题在日志里可见。
        tracing::error!(%error, "dataplane startup failed after registration");
    }
    serde_json::to_value(info).map_err(|e| e.to_string())
}

/// 每 2 秒轮询一次登录状态，直到终态；总预算 10 分钟。
/// 落定时刷新注册与数据面；失败原样透出给 login_poll。
fn spawn_login_poller(
    daemon: Arc<Daemon>,
    keys: Arc<KeyStore>,
    started: StartedLogin,
    coord_addr: String,
) {
    tokio::spawn(async move {
        let hostname = local_hostname();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(600);
        loop {
            if tokio::time::Instant::now() >= deadline {
                let error = "登录等待超时（10 分钟），请重新执行 hz up".to_string();
                tracing::error!(%error, "interactive login polling gave up");
                *daemon.login.lock().expect("login poisoned") = LoginProgress::Failed { error };
                return;
            }
            match poll_login_status(&daemon.state_dir, &hostname, &coord_addr, &started.login_id)
                .await
            {
                Ok(LoginPoll::Pending) => {}
                Ok(LoginPoll::Completed(info)) => {
                    if let Err(error) = finish_registration(&daemon, &keys, info, &coord_addr).await
                    {
                        *daemon.login.lock().expect("login poisoned") =
                            LoginProgress::Failed { error };
                        return;
                    }
                    *daemon.login.lock().expect("login poisoned") = LoginProgress::Completed;
                    return;
                }
                Ok(LoginPoll::Failed(error)) => {
                    tracing::warn!(%error, "interactive login failed");
                    *daemon.login.lock().expect("login poisoned") = LoginProgress::Failed { error };
                    return;
                }
                Err(error) => {
                    // 网络抖动等暂时性错误按 Pending 处理，等下一轮。
                    tracing::warn!(%error, "login status poll error, will retry");
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

fn peers_view(daemon: &Daemon) -> Vec<MapPeer> {
    let own_node_id = daemon
        .registration
        .lock()
        .expect("registration poisoned")
        .as_ref()
        .map(|info| info.node_id.clone());
    let ages = daemon
        .engine
        .lock()
        .expect("engine poisoned")
        .as_ref()
        .map(|engine| engine.handshake_ages())
        .unwrap_or_default();
    daemon
        .map_cache
        .snapshot()
        .into_iter()
        .filter(|node| own_node_id.as_deref() != Some(node.node_id.as_str()))
        .map(|node| MapPeer {
            handshake_secs: ages
                .get(&node.node_id)
                .and_then(|age| age.map(Duration::from))
                .map(|age| age.as_secs()),
            name: node.name,
            ipv4: node.ipv4,
            ipv6: node.ipv6,
            endpoints: node.endpoints,
        })
        .collect()
}

/// 拉起数据面：UDP socket（WireGuard、打洞与 STUN 共用）、TUN、Map 订阅、
/// Endpoint 收集、Relay 断线重连与路径管理。幂等。
async fn start_dataplane(
    daemon: &Arc<Daemon>,
    keys: &Arc<KeyStore>,
    info: &RegisteredInfo,
    coord_addr: &str,
) -> anyhow::Result<()> {
    if daemon.engine.lock().expect("engine poisoned").is_some() {
        return Ok(());
    }
    let port: u16 = std::env::var("HZD_WG_PORT")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(0);
    let engine = Arc::new(SocketEngine::bind(keys.node().clone(), port).await?);
    let endpoint = lan_endpoint(coord_addr, engine.local_addr().port()).await?;
    tracing::info!(%endpoint, "reporting lan endpoint");

    if let Ok(relay_addr) = std::env::var("HZD_RELAY_ADDR") {
        if !relay_addr.is_empty() {
            spawn_relay_supervisor(&engine, keys, &info.node_id, &relay_addr);
        }
    }

    spawn_tun_bridge(&engine, info);
    spawn_map_task(
        daemon.state_dir.clone(),
        daemon.map_cache.clone(),
        daemon.map_signal.clone(),
        daemon.use_relay.clone(),
        engine.clone(),
        info.node_id.clone(),
        endpoint.to_string(),
        coord_addr.to_string(),
    );
    spawn_endpoint_collector(
        daemon.state_dir.clone(),
        daemon.own_endpoints.clone(),
        engine.clone(),
        coord_addr.to_string(),
    );
    spawn_path_task(
        daemon.map_cache.clone(),
        daemon.map_signal.clone(),
        daemon.own_endpoints.clone(),
        daemon.use_relay.clone(),
        engine.clone(),
        keys.clone(),
        &info.node_id,
    );

    *daemon.engine.lock().expect("engine poisoned") = Some(engine);
    Ok(())
}

/// Relay 传输监督（#7 单连 → #8 断线重连）：连上后挂到引擎；流断开按退避
/// 重连。CA 路径（HZD_RELAY_CA_PATH）指向私有 CA 的 PEM。
fn spawn_relay_supervisor(
    engine: &Arc<SocketEngine>,
    keys: &Arc<KeyStore>,
    node_id: &str,
    relay_addr: &str,
) {
    let ca_pem = match std::env::var("HZD_RELAY_CA_PATH") {
        Ok(path) if !path.is_empty() => match std::fs::read_to_string(&path) {
            Ok(pem) => Some(pem),
            Err(error) => {
                tracing::warn!(%path, %error, "read relay CA failed, using system roots");
                None
            }
        },
        _ => None,
    };
    let engine = engine.clone();
    let keys = keys.clone();
    let node_id = node_id.to_string();
    let relay_addr = relay_addr.to_string();
    tokio::spawn(async move {
        let mut backoff = BACKOFF_START;
        loop {
            match hz_core::relay_client::connect_relay(
                &keys,
                &node_id,
                &relay_addr,
                ca_pem.as_deref(),
            )
            .await
            {
                Ok(client) => {
                    backoff = BACKOFF_START;
                    let client = Arc::new(client);
                    engine.set_relay(client.clone());
                    tracing::info!(%relay_addr, "relay transport connected");
                    client.wait_closed().await;
                    tracing::warn!(%relay_addr, "relay transport down, reconnecting");
                }
                Err(error) => {
                    tracing::warn!(%error, %relay_addr, "relay transport unavailable");
                }
            }
            tokio::time::sleep(jittered(backoff)).await;
            backoff = backoff.saturating_mul(2).min(BACKOFF_CAP);
        }
    });
}

/// STUN 服务器地址：显式 HZD_STUN_ADDR 优先，否则从 HZD_RELAY_ADDR 的主机
/// 推导（FR-8：STUN 与 Relay 同主机，UDP 3478）。
fn stun_server_addr() -> Option<SocketAddr> {
    if let Ok(addr) = std::env::var("HZD_STUN_ADDR") {
        return addr.parse().ok();
    }
    let relay = std::env::var("HZD_RELAY_ADDR").ok()?;
    let host_port = relay
        .rsplit_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(&relay);
    let host = host_port
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(host_port);
    format!("{host}:3478").parse().ok()
}

/// Endpoint 收集与上报（FR-8）：周期性收集 Lan/STUN/V6，ReportEndpoints 落库，
/// 结果同时存进共享槽供打洞信令取本机候选。
fn spawn_endpoint_collector(
    state_dir: PathBuf,
    own_slot: Arc<StdMutex<Vec<DiscoveredEndpoint>>>,
    engine: Arc<SocketEngine>,
    coord_addr: String,
) {
    let stun_server = stun_server_addr();
    if stun_server.is_none() {
        tracing::debug!("no stun server configured (HZD_STUN_ADDR / HZD_RELAY_ADDR)");
    }
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(ENDPOINT_COLLECT_EVERY);
        loop {
            ticker.tick().await;
            let stun_mapped = match stun_server {
                Some(server) => match engine.stun_query(server).await {
                    Ok(mapped) => {
                        tracing::info!(%mapped, "stun mapped endpoint discovered");
                        Some(mapped)
                    }
                    Err(error) => {
                        tracing::warn!(%server, %error, "stun query failed");
                        None
                    }
                },
                None => None,
            };
            let found = endpoint::collect(engine.local_addr().port(), stun_mapped);
            tracing::info!(endpoints = ?found, "collected endpoints");
            *own_slot.lock().expect("own endpoints poisoned") = found.clone();
            if let Err(error) = report_endpoints(&state_dir, &found, &coord_addr).await {
                tracing::warn!(%error, "endpoint report to coord failed");
            }
        }
    });
}

/// 路径管理任务（FR-8）：每秒推进状态机 + Map 变化、打洞信令即时唤醒。
/// 产出的事件在这里执行：切引擎传输开关（带日志）、发打洞握手、经 Relay
/// 收发 PunchOffer/PunchAck。HZD_FORCE_RELAY=1 时全部对端钉在 Relay。
fn spawn_path_task(
    cache: Arc<NetworkMapCache>,
    map_signal: Arc<tokio::sync::Notify>,
    own_slot: Arc<StdMutex<Vec<DiscoveredEndpoint>>>,
    use_relay_slot: Arc<StdMutex<HashMap<String, bool>>>,
    engine: Arc<SocketEngine>,
    keys: Arc<KeyStore>,
    own_node_id: &str,
) {
    let own_node_id = own_node_id.to_string();
    let (punch_tx, punch_rx) = mpsc::channel::<Vec<u8>>(64);
    engine.set_punch_handler(punch_tx);
    let mut punch_rx = punch_rx;
    tokio::spawn(async move {
        let mut manager = PathManager::new();
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = map_signal.notified() => {}
                frame = punch_rx.recv() => {
                    match frame {
                        Some(frame) => {
                            handle_punch_frame(
                                &cache, &own_node_id, &engine, &keys, &mut manager, &frame,
                            )
                            .await;
                        }
                        None => return,
                    }
                }
            }
            let peers = peer_endpoint_view(&cache, &own_node_id);
            let direct_rx = engine.direct_rx_ages();
            let events = manager.tick(
                std::time::Instant::now(),
                &peer_endpoints_of(&peers),
                &direct_rx,
            );
            for event in events {
                apply_path_event(&engine, &own_slot, &use_relay_slot, &keys, &peers, event).await;
            }
        }
    });
}

/// 路径任务的对端视图：Endpoint 分组 + 数据面公钥（打洞信令加密用）。
struct PeerView {
    endpoints: PeerEndpoints,
    node_key: [u8; 32],
}

fn peer_endpoints_of(views: &[PeerView]) -> Vec<PeerEndpoints> {
    views.iter().map(|view| view.endpoints.clone()).collect()
}

/// Map 缓存 → 路径状态机的对端视图（node key + 按来源分组的候选 Endpoint）。
fn peer_endpoint_view(cache: &NetworkMapCache, own_node_id: &str) -> Vec<PeerView> {
    cache
        .snapshot()
        .into_iter()
        .filter(|node| node.node_id != own_node_id)
        .filter_map(|node| {
            let node_key: [u8; 32] = node.node_key_pub.clone().try_into().ok()?;
            let mut endpoints = PeerEndpoints {
                node_id: node.node_id.clone(),
                ..Default::default()
            };
            for detailed in &node.detailed_endpoints {
                let Some(addr) = detailed.socket_addr() else {
                    continue;
                };
                match detailed.kind() {
                    hz_core::endpoint::EndpointKind::V6 => endpoints.v6.push(addr),
                    hz_core::endpoint::EndpointKind::Stun => endpoints.stun.push(addr),
                    hz_core::endpoint::EndpointKind::Lan => endpoints.lan.push(addr),
                }
            }
            Some(PeerView {
                endpoints,
                node_key,
            })
        })
        .collect()
}

async fn apply_path_event(
    engine: &Arc<SocketEngine>,
    own_slot: &Arc<StdMutex<Vec<DiscoveredEndpoint>>>,
    use_relay_slot: &Arc<StdMutex<HashMap<String, bool>>>,
    keys: &Arc<KeyStore>,
    peers: &[PeerView],
    event: PathEvent,
) {
    let forced = force_relay();
    match event {
        PathEvent::SetUseRelay { node_id, use_relay } => {
            let use_relay = use_relay || forced;
            use_relay_slot
                .lock()
                .expect("use_relay poisoned")
                .insert(node_id.clone(), use_relay);
            engine.set_use_relay(&node_id, use_relay);
            if use_relay {
                tracing::info!(node_id = %node_id, "path=relay (direct lost, fall back)");
            } else {
                // IPv6 直连优先（FR-8）：双方都有 v6 候选时，把发送偏好
                // 切到 v6——打洞握手两族并发，先回来的可能是 v4。
                if let Some(peer) = peers.iter().find(|peer| peer.endpoints.node_id == node_id) {
                    if let Some(v6) = peer.endpoints.v6.first() {
                        engine.prefer_endpoint(&node_id, *v6);
                    }
                }
                let endpoint = engine
                    .endpoint_candidates(&node_id)
                    .first()
                    .map(|addr| addr.to_string())
                    .unwrap_or_default();
                tracing::info!(node_id = %node_id, %endpoint, "path=direct");
            }
        }
        PathEvent::SendHandshake { node_id } => {
            if forced {
                return;
            }
            engine.send_punch(&node_id).await;
        }
        PathEvent::SendOffer { node_id } => {
            if forced {
                return;
            }
            let Some(relay) = engine.relay_client() else {
                tracing::debug!(%node_id, "punch offer skipped: no relay transport");
                return;
            };
            let Some(peer) = peers.iter().find(|peer| peer.endpoints.node_id == node_id) else {
                return;
            };
            let codec = PunchCodec::new(keys.node(), &peer.node_key);
            let mut nonce = [0u8; 16];
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut nonce);
            let candidates = own_slot
                .lock()
                .expect("own endpoints poisoned")
                .iter()
                .map(|found| found.addr)
                .collect::<Vec<_>>();
            let offer = PunchMessage::Offer {
                nonce,
                ts_unix: hz_core::punch::now_unix(),
                candidates,
            };
            relay.send_datagram(&node_id, codec.seal(&offer)).await;
        }
        PathEvent::SendAck { node_id, chosen } => {
            if forced {
                return;
            }
            let Some(relay) = engine.relay_client() else {
                return;
            };
            let Some(peer) = peers.iter().find(|peer| peer.endpoints.node_id == node_id) else {
                return;
            };
            let codec = PunchCodec::new(keys.node(), &peer.node_key);
            let ack = PunchMessage::Ack { chosen };
            relay.send_datagram(&node_id, codec.seal(&ack)).await;
        }
    }
}

/// 处理一条入站打洞信令：对每个在册对端试解密（帧不带明文发送方，AEAD
/// 密钥按对端唯一，试全对端即可归队）。Offer 记下候选并立即回握手 + Ack；
/// Ack 触发一次握手。
async fn handle_punch_frame(
    cache: &Arc<NetworkMapCache>,
    own_node_id: &str,
    engine: &Arc<SocketEngine>,
    keys: &Arc<KeyStore>,
    manager: &mut PathManager,
    frame: &[u8],
) {
    if force_relay() {
        return;
    }
    let now = hz_core::punch::now_unix();
    for peer in peer_endpoint_view(cache, own_node_id) {
        let codec = PunchCodec::new(keys.node(), &peer.node_key);
        let Some(message) = codec.open(frame, now) else {
            continue;
        };
        manager.note_punch_signal(&peer.endpoints.node_id, std::time::Instant::now());
        match message {
            PunchMessage::Offer { candidates, .. } => {
                tracing::info!(
                    node_id = %peer.endpoints.node_id,
                    candidates = ?candidates,
                    "punch offer received"
                );
                engine.add_peer_endpoints(&peer.endpoints.node_id, candidates.clone());
                engine.send_punch(&peer.endpoints.node_id).await;
                if let Some(chosen) = candidates.first().copied() {
                    if let Some(relay) = engine.relay_client() {
                        let ack = PunchMessage::Ack { chosen };
                        relay
                            .send_datagram(&peer.endpoints.node_id, codec.seal(&ack))
                            .await;
                    }
                }
            }
            PunchMessage::Ack { chosen } => {
                // Ack 只确认对端已朝我们的候选出洞；不再额外触发握手，
                // 避免反复强制重置 boringtun 的进行中握手（ Relay 会话会被饿死）。
                tracing::info!(node_id = %peer.endpoints.node_id, %chosen, "punch ack received");
            }
        }
        return;
    }
    tracing::debug!("punch frame matched no known peer, dropping");
}

/// TUN 读到的包进引擎，引擎解密的包写回 TUN。TUN 不可用时只保留引擎收发。
fn spawn_tun_bridge(engine: &Arc<SocketEngine>, info: &RegisteredInfo) {
    let (to_tunnel_tx, to_tunnel_rx) = mpsc::channel::<Vec<u8>>(256);
    tokio::spawn({
        let engine = engine.clone();
        async move {
            if let Err(error) = engine.run(to_tunnel_tx).await {
                tracing::error!(%error, "wireguard engine loop exited");
            }
        }
    });

    #[cfg(target_os = "linux")]
    {
        let mut to_tunnel_rx = to_tunnel_rx;
        let (ipv4, ipv6) = match (info.ipv4.parse(), info.ipv6.parse()) {
            (Ok(ipv4), Ok(ipv6)) => (ipv4, ipv6),
            _ => {
                tracing::warn!(
                    ipv4 = %info.ipv4,
                    ipv6 = %info.ipv6,
                    "registration holds invalid address, skip tun setup"
                );
                spawn_tunnel_drain(to_tunnel_rx);
                return;
            }
        };
        let tun_config = TunConfig {
            ipv4,
            ipv6,
            v4_cidr: std::env::var("HZD_V4_CIDR").unwrap_or_else(|_| DEFAULT_V4_CIDR.to_string()),
        };
        match Tun::setup(&tun_config) {
            Ok(tun) => {
                let device = tun.device();
                tokio::spawn({
                    let device = device.clone();
                    async move {
                        while let Some(packet) = to_tunnel_rx.recv().await {
                            if let Err(error) = device.send(&packet).await {
                                tracing::error!(%error, "tun write failed");
                                break;
                            }
                        }
                    }
                });
                let engine = engine.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65_535];
                    loop {
                        match device.recv(&mut buf).await {
                            Ok(len) => engine.send_ip_packet(&buf[..len]).await,
                            Err(error) => {
                                tracing::error!(%error, "tun read failed");
                                break;
                            }
                        }
                    }
                });
            }
            Err(error) => {
                tracing::warn!(%error, "tun setup failed, running without data plane forwarding");
                spawn_tunnel_drain(to_tunnel_rx);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = info;
        spawn_tunnel_drain(to_tunnel_rx);
    }
}

/// 无 TUN 时丢弃解密包，防 channel 满背压拖住引擎循环。
#[allow(clippy::unused_async)]
async fn drain_tunnel(mut rx: mpsc::Receiver<Vec<u8>>) {
    while rx.recv().await.is_some() {}
}

fn spawn_tunnel_drain(rx: mpsc::Receiver<Vec<u8>>) {
    tokio::spawn(drain_tunnel(rx));
}

/// Network Map 消费任务（FR-6）：启动即用本地缓存配置数据面（Coordination
/// Server 不可达也照常），然后循环 订阅 → 消费差量/全量 → 断线退避重连。
/// 每次重连都重新走挑战认证并重报 Endpoint（服务端在流打开时落库）。
/// Map 有实际变化时唤醒路径任务（打洞轮次紧跟对端 Endpoint 更新）。
#[allow(clippy::too_many_arguments)]
fn spawn_map_task(
    state_dir: PathBuf,
    cache: Arc<NetworkMapCache>,
    map_signal: Arc<tokio::sync::Notify>,
    use_relay: Arc<StdMutex<HashMap<String, bool>>>,
    engine: Arc<SocketEngine>,
    own_node_id: String,
    endpoint: String,
    coord_addr: String,
) {
    tokio::spawn(async move {
        let decisions = use_relay.lock().expect("use_relay poisoned").clone();
        apply_cache_to_engine(&cache, &engine, &own_node_id, &decisions);
        let mut backoff = BACKOFF_START;
        loop {
            match open_network_map_stream(&state_dir, vec![endpoint.clone()], &coord_addr).await {
                Ok(mut stream) => {
                    backoff = BACKOFF_START;
                    tracing::info!(%coord_addr, "network map stream opened");
                    loop {
                        let message = match stream.message().await {
                            Ok(Some(message)) => message,
                            Ok(None) => {
                                tracing::warn!("network map stream closed by server");
                                break;
                            }
                            Err(error) => {
                                tracing::warn!(%error, "network map stream error");
                                break;
                            }
                        };
                        if let Some(kind) = message.kind {
                            let change = match kind {
                                hz_proto::network_map_message::Kind::Full(map) => cache
                                    .apply_full(map.nodes.into_iter().map(MapNode::from).collect()),
                                hz_proto::network_map_message::Kind::Delta(delta) => cache
                                    .apply_delta(
                                        delta
                                            .added_or_updated
                                            .into_iter()
                                            .map(MapNode::from)
                                            .collect(),
                                        delta.removed_node_ids,
                                    ),
                            };
                            if !change.is_empty() {
                                tracing::info!(
                                    added = change.added_or_updated.len(),
                                    removed = change.removed_node_ids.len(),
                                    version = cache.version(),
                                    "network map updated"
                                );
                                let decisions =
                                    use_relay.lock().expect("use_relay poisoned").clone();
                                apply_cache_to_engine(&cache, &engine, &own_node_id, &decisions);
                                map_signal.notify_one();
                            }
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "network map subscription failed");
                }
            }
            tokio::time::sleep(jittered(backoff)).await;
            backoff = backoff.saturating_mul(2).min(BACKOFF_CAP);
        }
    });
}

/// 用缓存当前快照对账数据面（含自己之外的全部对端）。use_relay 是路径管理
/// 的当前决定（node_id → 走 Relay）；没有决定的按 HZD_FORCE_RELAY 兜底。
fn apply_cache_to_engine(
    cache: &NetworkMapCache,
    engine: &SocketEngine,
    own_node_id: &str,
    use_relay: &HashMap<String, bool>,
) {
    let specs = cache
        .snapshot()
        .into_iter()
        .filter(|node| node.node_id != own_node_id)
        .filter_map(|node| peer_spec(&node, use_relay))
        .collect::<Vec<_>>();
    engine.reconcile(specs);
}

/// 退避加抖动：附加 0 到一半退避时长的随机量（取自系统时钟亚秒，避免引入
/// 新依赖），避免大量 Node 同步重连打爆服务端。
fn jittered(backoff: Duration) -> Duration {
    let subsec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_millis() as u64)
        .unwrap_or(0);
    let spread = backoff.as_millis() as u64 / 2 + 1;
    backoff + Duration::from_millis(subsec % spread)
}

fn peer_spec(node: &MapNode, use_relay: &HashMap<String, bool>) -> Option<PeerSpec> {
    let node_key_pub: [u8; 32] = node.node_key_pub.clone().try_into().ok()?;
    let ipv4: IpAddr = node.ipv4.parse().ok()?;
    let ipv6: IpAddr = node.ipv6.parse().ok()?;
    // 候选序 = 打洞优先序（FR-8）：V6 → Stun → Lan，同类保持上报顺序。
    let ranked = hz_core::endpoint::rank(
        &node
            .detailed_endpoints
            .iter()
            .filter_map(|detailed| {
                detailed
                    .socket_addr()
                    .map(|addr| hz_core::endpoint::DiscoveredEndpoint {
                        addr,
                        kind: detailed.kind(),
                    })
            })
            .collect::<Vec<_>>(),
    );
    let mut endpoints = ranked.iter().map(|found| found.addr).collect::<Vec<_>>();
    // 详细视图缺失（旧 Coordination Server / 旧缓存）时退回字符串视图。
    if endpoints.is_empty() {
        endpoints = node
            .endpoints
            .iter()
            .filter_map(|text| text.parse().ok())
            .collect();
    }
    Some(PeerSpec {
        node_id: node.node_id.clone(),
        node_key_pub,
        endpoints,
        dst_addrs: vec![ipv4, ipv6],
        // 默认走 Relay（FR-8 连通优先），路径管理打洞成功后切直连；
        // HZD_FORCE_RELAY=1 在事件应用处把一切直连决定压回 Relay。
        use_relay: use_relay.get(&node.node_id).copied().unwrap_or(true),
    })
}

fn force_relay() -> bool {
    std::env::var("HZD_FORCE_RELAY").ok().as_deref() == Some("1")
}

/// registration.json 的落盘形态：注册身份 + 记下 coord 地址供重启后自动重连；
/// 老文件没有 coord_addr 字段也能装载。
#[derive(Debug, Serialize, Deserialize)]
struct RegistrationFile {
    #[serde(flatten)]
    info: RegisteredInfo,
    #[serde(default)]
    coord_addr: Option<String>,
}

fn load_registration(state_dir: &Path) -> anyhow::Result<Option<RegistrationFile>> {
    let path = state_dir.join(REGISTRATION_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).map_err(|error| anyhow::anyhow!("读取 {path:?} 失败：{error}"));
        }
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("{path:?} 内容损坏：{error}"))
}

fn save_registration(
    state_dir: &Path,
    info: &RegisteredInfo,
    coord_addr: &str,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let path = state_dir.join(REGISTRATION_FILE);
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(
            serde_json::to_string_pretty(&RegistrationFile {
                info: info.clone(),
                coord_addr: Some(coord_addr.to_string()),
            })?
            .as_bytes(),
        )?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
