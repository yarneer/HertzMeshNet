//! hzd 守护进程主体：状态目录、密钥、UDS 服务、注册与数据面。
//! 数据面 = 一个 [`SocketEngine`]（WireGuard over UDP）+ hz0 TUN + Network Map 订阅；
//! TUN 不可用时降级为纯控制面（注册与状态照常），方便无 root 环境跑测试。
//! main 只负责 tracing 初始化与 Ctrl-C；守护化（systemd/launchd 托管）不在本进程内做。
//! 注册结果持久化在状态目录的 registration.json（0600），重启后仍是 Registered。

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use hz_core::coord_client::{
    DEFAULT_COORD_ADDR, LoginPoll, StartedLogin, begin_interactive_login, local_hostname,
    open_network_map_stream, poll_login_status, register_with_auth_key,
};
use hz_core::ipc::{self, Handler};
use hz_core::keys::KeyStore;
use hz_core::map::{MapNode, NetworkMapCache};
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

/// 拉起数据面：UDP socket（WireGuard 与后续打洞共用）、TUN、Map 订阅。幂等。
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
            connect_relay_transport(&engine, keys, &info.node_id, &relay_addr).await;
        }
    }

    spawn_tun_bridge(&engine, info);
    spawn_map_task(
        daemon.state_dir.clone(),
        daemon.map_cache.clone(),
        engine.clone(),
        info.node_id.clone(),
        endpoint.to_string(),
        coord_addr.to_string(),
    );

    *daemon.engine.lock().expect("engine poisoned") = Some(engine);
    Ok(())
}

/// 接入 Relay 中继传输（#7）。连接失败只降级（直连路径不受影响），
/// CA 路径（HZD_RELAY_CA_PATH）指向私有 CA 的 PEM，供自签部署的 Relay 使用。
async fn connect_relay_transport(
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
    match hz_core::relay_client::connect_relay(keys, node_id, relay_addr, ca_pem.as_deref()).await {
        Ok(client) => {
            engine.set_relay(Arc::new(client));
            tracing::info!(%relay_addr, "relay transport connected");
        }
        Err(error) => tracing::warn!(%error, %relay_addr, "relay transport unavailable"),
    }
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
fn spawn_map_task(
    state_dir: PathBuf,
    cache: Arc<NetworkMapCache>,
    engine: Arc<SocketEngine>,
    own_node_id: String,
    endpoint: String,
    coord_addr: String,
) {
    tokio::spawn(async move {
        apply_cache_to_engine(&cache, &engine, &own_node_id);
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
                                apply_cache_to_engine(&cache, &engine, &own_node_id);
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

/// 用缓存当前快照对账数据面（含自己之外的全部对端）。
fn apply_cache_to_engine(cache: &NetworkMapCache, engine: &SocketEngine, own_node_id: &str) {
    let specs = cache
        .snapshot()
        .into_iter()
        .filter(|node| node.node_id != own_node_id)
        .filter_map(|node| peer_spec(&node))
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

fn peer_spec(node: &MapNode) -> Option<PeerSpec> {
    let node_key_pub: [u8; 32] = node.node_key_pub.clone().try_into().ok()?;
    let ipv4: IpAddr = node.ipv4.parse().ok()?;
    let ipv6: IpAddr = node.ipv6.parse().ok()?;
    let endpoints: Vec<SocketAddr> = node
        .endpoints
        .iter()
        .filter_map(|text| text.parse().ok())
        .collect();
    Some(PeerSpec {
        node_id: node.node_id.clone(),
        node_key_pub,
        endpoints,
        dst_addrs: vec![ipv4, ipv6],
        // HZD_FORCE_RELAY=1：全部对端走 Relay（对称型 NAT 等无法直连拓扑的
        // 确定性策略）。按 Endpoint 优先的路径选择归 #8。
        use_relay: force_relay(),
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
