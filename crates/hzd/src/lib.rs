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
use hz_core::status::{NodeStatus, RegisteredInfo};
#[cfg(target_os = "linux")]
use hz_core::tun::{DEFAULT_V4_CIDR, Tun, TunConfig};
use hz_core::wire::{PeerSpec, SocketEngine, lan_endpoint};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::mpsc;

const REGISTRATION_FILE: &str = "registration.json";

/// 一次交互式登录在 hzd 内的进度；终态只保留最后一次，重复 up 覆盖。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum LoginProgress {
    Idle,
    Pending,
    Completed,
    Failed { error: String },
}

/// `hz status` 展示的一个对端；来源于最近一次 Network Map。
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MapPeer {
    pub name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub endpoints: Vec<String>,
    pub handshake_secs: Option<u64>,
}

/// Map 快照里保留的对端（含 node_id，供握手时长联查）。
#[derive(Debug, Clone)]
struct PeerSnapshot {
    node_id: String,
    name: String,
    ipv4: String,
    ipv6: String,
    endpoints: Vec<String>,
}

struct Daemon {
    state_dir: PathBuf,
    registration: StdMutex<Option<RegisteredInfo>>,
    peers: Arc<StdMutex<Vec<PeerSnapshot>>>,
    engine: StdMutex<Option<Arc<SocketEngine>>>,
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
    let daemon = Arc::new(Daemon {
        state_dir,
        registration: StdMutex::new(registration),
        peers: Arc::new(StdMutex::new(Vec::new())),
        engine: StdMutex::new(None),
        login: StdMutex::new(LoginProgress::Idle),
    });

    // 开机即已注册：直接拉起数据面（coord 地址此时只能来自环境变量）。
    let boot_info = daemon
        .registration
        .lock()
        .expect("registration poisoned")
        .clone();
    if let Some(info) = boot_info {
        let coord_addr =
            std::env::var("HZD_COORD_ADDR").unwrap_or_else(|_| DEFAULT_COORD_ADDR.to_string());
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
    save_registration(&daemon.state_dir, &info).map_err(|error| format!("{error:#}"))?;
    *daemon.registration.lock().expect("registration poisoned") = Some(info.clone());
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
    let snapshots = daemon.peers.lock().expect("peers poisoned").clone();
    let ages = daemon
        .engine
        .lock()
        .expect("engine poisoned")
        .as_ref()
        .map(|engine| engine.handshake_ages())
        .unwrap_or_default();
    snapshots
        .into_iter()
        .map(|snapshot| MapPeer {
            handshake_secs: ages
                .get(&snapshot.node_id)
                .and_then(|age| age.map(Duration::from))
                .map(|age| age.as_secs()),
            name: snapshot.name,
            ipv4: snapshot.ipv4,
            ipv6: snapshot.ipv6,
            endpoints: snapshot.endpoints,
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

    spawn_tun_bridge(&engine, info);
    spawn_map_subscription(
        daemon.state_dir.clone(),
        daemon.peers.clone(),
        engine.clone(),
        info.node_id.clone(),
        endpoint.to_string(),
        coord_addr.to_string(),
    );

    *daemon.engine.lock().expect("engine poisoned") = Some(engine);
    Ok(())
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

fn spawn_map_subscription(
    state_dir: PathBuf,
    peers: Arc<StdMutex<Vec<PeerSnapshot>>>,
    engine: Arc<SocketEngine>,
    own_node_id: String,
    endpoint: String,
    coord_addr: String,
) {
    tokio::spawn(async move {
        let mut stream =
            match open_network_map_stream(&state_dir, vec![endpoint], &coord_addr).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::error!(%error, "network map subscription failed");
                    return;
                }
            };
        loop {
            match stream.message().await {
                Ok(Some(message)) => {
                    let Some(hz_proto::network_map_message::Kind::Full(map)) = message.kind else {
                        continue;
                    };
                    let mut snapshots = Vec::new();
                    let mut specs = Vec::new();
                    for node in &map.nodes {
                        if node.node_id == own_node_id {
                            continue;
                        }
                        match peer_spec(node) {
                            Some(spec) => {
                                snapshots.push(PeerSnapshot {
                                    node_id: node.node_id.clone(),
                                    name: node.name.clone(),
                                    ipv4: node.ipv4.clone(),
                                    ipv6: node.ipv6.clone(),
                                    endpoints: node.endpoints.clone(),
                                });
                                specs.push(spec);
                            }
                            None => {
                                tracing::warn!(
                                    node_id = %node.node_id,
                                    "map entry unusable (bad key/address/endpoint), skipped"
                                );
                            }
                        }
                    }
                    tracing::info!(peers = snapshots.len(), "network map applied");
                    *peers.lock().expect("peers poisoned") = snapshots;
                    engine.reconcile(specs);
                }
                Ok(None) => {
                    tracing::warn!("network map stream closed by server");
                    break;
                }
                Err(error) => {
                    tracing::error!(%error, "network map stream error");
                    break;
                }
            }
        }
    });
}

fn peer_spec(node: &hz_proto::NodeInfo) -> Option<PeerSpec> {
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
    })
}

fn load_registration(state_dir: &Path) -> anyhow::Result<Option<RegisteredInfo>> {
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

fn save_registration(state_dir: &Path, info: &RegisteredInfo) -> anyhow::Result<()> {
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
        file.write_all(serde_json::to_string_pretty(info)?.as_bytes())?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
