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
    DEFAULT_COORD_ADDR, LoginPoll, PunchCounters, StartedLogin, admin_create_auth_key,
    admin_revoke_auth_key, begin_interactive_login, delete_node, list_nodes, local_hostname,
    open_network_map_stream, policy_get, policy_push, policy_rollback, poll_login_status,
    register_with_auth_key, rename_node, report_endpoints, revoke_node,
};
use hz_core::endpoint::{self, DiscoveredEndpoint};
use hz_core::ipc::{self, Handler};
use hz_core::keys::{KeyStore, NodeStaticSecret};
use hz_core::map::{MapNode, NetworkMapCache};
use hz_core::netwatch::{self, NetEvent};
use hz_core::path::{PathEvent, PathManager, PeerEndpoints};
use hz_core::policy::{InboundGate, InboundPolicyView};
use hz_core::punch::{PunchCodec, PunchMessage};
use hz_core::status::{NodeStatus, RegisteredInfo};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use hz_core::tun::{DEFAULT_V4_CIDR, Tun, TunConfig};
use hz_core::wire::{PeerReport, PeerSpec, SocketEngine, lan_endpoint};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;

pub mod dns;
pub mod launchd;
pub mod ping;

const REGISTRATION_FILE: &str = "registration.json";

/// 断线重连退避：1s 起步、翻倍、30s 封顶（叠加亚秒抖动）。
const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Endpoint 收集与上报周期（FR-8）。
const ENDPOINT_COLLECT_EVERY: Duration = Duration::from_secs(30);

/// 过期驻留时的轮询间隔：Network Map 订阅暂停，等待重新登录翻转状态。
const EXPIRED_POLL: Duration = Duration::from_secs(2);

/// 守护进程视角的注册会话状态机：Registered 与 Expired 共享同一份身份，
/// 区别只在能否通信。Expired 不删除任何本地状态（ADR-0005：重新登录保身份）。
#[derive(Debug, Clone)]
enum Session {
    None,
    Registered(RegisteredInfo),
    Expired(RegisteredInfo),
}

impl Session {
    fn info(&self) -> Option<RegisteredInfo> {
        match self {
            Session::None => None,
            Session::Registered(info) | Session::Expired(info) => Some(info.clone()),
        }
    }
}

/// 一次交互式登录在 hzd 内的进度；终态只保留最后一次，重复 up 覆盖。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum LoginProgress {
    Idle,
    Pending,
    Completed,
    Failed { error: String },
}

/// `hz status` 展示的一个对端；来源于本地 Network Map 缓存 + 数据面现状。
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MapPeer {
    pub name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub endpoints: Vec<String>,
    pub handshake_secs: Option<u64>,
    /// 当前路径："direct" / "relay"；数据面未拉起时为 null。
    pub path: Option<String>,
    /// 直连时在用的 Endpoint（Relayed 时为 null）。
    pub endpoint: Option<String>,
}

/// 物理出口变化代数（FR-8 网络变化恢复）。恢复序列递增它；到 Coordination
/// Server 与 Relay 的长连接任务在等待期间监视它，变化即主动断线重拨——
/// 出口切换后旧 TCP 只能靠 keepalive 超时发现（秒到分钟级），等不起。
/// watch 语义保证递增先于订阅也不会丢：接收方比对的是见过的值。
#[derive(Clone)]
struct EgressEpoch(tokio::sync::watch::Sender<u64>);

impl EgressEpoch {
    fn new() -> Self {
        Self(tokio::sync::watch::Sender::new(0))
    }

    fn bump(&self) {
        self.0.send_modify(|generation| *generation += 1);
    }

    fn receiver(&self) -> tokio::sync::watch::Receiver<u64> {
        self.0.subscribe()
    }
}

struct Daemon {
    state_dir: PathBuf,
    registration: StdMutex<Session>,
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
    /// 入站过滤闸（A1）：Map 流带来的 Policy 视图驱动，TUN 写入路径查询。
    policy_gate: Arc<InboundGate>,
    /// 路径管理的累计打洞计数（FR-12 打洞成功率的上报源）。
    punch: Arc<StdMutex<PunchCounters>>,
    /// 等待中的 ping 探针（应答到达时唤醒）。
    probes: Arc<ping::Probes>,
    /// 本 Node 已被 Admin 吊销（区别于过期：重新登录救不回来）。
    /// 到期/吊销共享 Expired 会话态，此标记决定 `hz status` 的文案。
    revoked: StdMutex<bool>,
    /// 物理出口变化代数：长连接任务据此强制重拨（见类型注释）。
    egress_epoch: EgressEpoch,
}

impl Daemon {
    fn registration_info(&self) -> Option<RegisteredInfo> {
        self.registration
            .lock()
            .expect("registration poisoned")
            .info()
    }

    /// 到期/吊销反应（FR-3）：记录 Expired 状态、拆掉全部对端隧道，
    /// TUN 与本地身份保持原样，等 `hz up` 重新登录。重复触发是空操作。
    fn mark_expired(&self, engine: &SocketEngine) {
        let mut registration = self.registration.lock().expect("registration poisoned");
        match &*registration {
            Session::Registered(_) => {
                *registration =
                    Session::Expired(registration.info().expect("checked above in match"));
            }
            Session::Expired(_) | Session::None => return,
        }
        drop(registration);
        engine.reconcile(Vec::new());
        tracing::warn!(
            "own node removed from network map (expired or revoked); \
             data plane down until interactive re-login"
        );
    }

    fn is_expired(&self) -> bool {
        matches!(
            &*self.registration.lock().expect("registration poisoned"),
            Session::Expired(_)
        )
    }
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
        registration: StdMutex::new(
            registration
                .as_ref()
                .map(|file| Session::Registered(file.info.clone()))
                .unwrap_or(Session::None),
        ),
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
        policy_gate: Arc::new(InboundGate::new()),
        punch: Arc::new(StdMutex::new(PunchCounters::default())),
        probes: Arc::new(ping::Probes::default()),
        revoked: StdMutex::new(false),
        egress_epoch: EgressEpoch::new(),
    });

    // 开机即已注册：直接拉起数据面；coord 地址取注册时记下的，其次环境变量。
    // 上次运行期间是否已过期不落盘：由 Map 订阅被拒（已过期）在线发现。
    let boot_info = daemon.registration_info();
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
                Session::Registered(info) => NodeStatus::Registered(info),
                Session::Expired(info) => NodeStatus::Expired(info),
                Session::None => {
                    return serde_json::to_value(NodeStatus::Unregistered)
                        .map_err(|e| e.to_string());
                }
            };
            let mut value = serde_json::to_value(status).map_err(|e| e.to_string())?;
            value["peers"] =
                serde_json::to_value(peers_view(&daemon)).map_err(|e| e.to_string())?;
            value["dns_suffix"] = serde_json::json!(hz_core::dns::dns_suffix());
            value["revoked"] = serde_json::json!(*daemon.revoked.lock().expect("revoked poisoned"));
            value["policy"] = serde_json::json!({
                "version": daemon.policy_gate.version(),
                "dropped": daemon.policy_gate.dropped(),
            });
            Ok(value)
        }
        "ping" => {
            let target = request
                .params
                .get("node")
                .and_then(Value::as_str)
                .ok_or_else(|| "缺少 node 参数（Node Name 或 node id）".to_string())?;
            ping_peer(&daemon, target).await
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
                    // CLI 打印，轮询在后台任务里继续。已注册（含已过期）的 Node
                    // 重新登录按 ADR-0005 轮换 Node Key：先在内存暂存新密钥对，
                    // 新公钥随 BeginLoginRequest 上行，登录完成才落盘生效。
                    let already_registered = daemon.registration_info().is_some();
                    let staged = already_registered.then(|| keys.stage_node_rotation());
                    let node_key_pub = staged
                        .as_ref()
                        .map(|(_, public)| *public)
                        .unwrap_or_else(|| keys.node_public());
                    let started = begin_interactive_login(
                        &daemon.state_dir,
                        &local_hostname(),
                        &coord_addr,
                        node_key_pub,
                    )
                    .await
                    .map_err(|error| format!("{error:#}"))?;
                    *daemon.login.lock().expect("login poisoned") = LoginProgress::Pending;
                    let login_url = started.login_url.clone();
                    let expires_unix = started.expires_unix;
                    let staged_secret = staged.map(|(secret, _)| secret);
                    spawn_login_poller(
                        daemon.clone(),
                        keys.clone(),
                        started,
                        coord_addr,
                        staged_secret,
                    );
                    Ok(serde_json::json!({
                        "login_url": login_url,
                        "expires_unix": expires_unix,
                    }))
                }
            }
        }
        "policy_push" => {
            let coord_addr = daemon_coord_addr(&daemon)?;
            let content = request
                .params
                .get("content")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "缺少 Policy 内容".to_string())?
                .to_string();
            let version = policy_push(&daemon.state_dir, &coord_addr, &content)
                .await
                .map_err(|error| format!("{error:#}"))?;
            Ok(serde_json::json!({ "version": version }))
        }
        "policy_get" => {
            let coord_addr = daemon_coord_addr(&daemon)?;
            let snapshot = policy_get(&daemon.state_dir, &coord_addr)
                .await
                .map_err(|error| format!("{error:#}"))?;
            let history: Vec<serde_json::Value> = snapshot
                .history
                .iter()
                .map(|entry| {
                    serde_json::json!({
                        "version": entry.version,
                        "created_at_unix": entry.created_at_unix,
                    })
                })
                .collect();
            Ok(serde_json::json!({
                "version": snapshot.version,
                "content": snapshot.content,
                "history": history,
            }))
        }
        "policy_rollback" => {
            let coord_addr = daemon_coord_addr(&daemon)?;
            let version = request
                .params
                .get("version")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| "缺少回滚目标版本号".to_string())?;
            let rolled = policy_rollback(&daemon.state_dir, &coord_addr, version)
                .await
                .map_err(|error| format!("{error:#}"))?;
            Ok(serde_json::json!({ "version": rolled }))
        }
        "authkey_create" => {
            let coord_addr = daemon_coord_addr(&daemon)?;
            let expires_unix = request
                .params
                .get("expires_unix")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| "缺少 expires_unix（Auth Key 过期时刻，unix 秒）".to_string())?;
            let single_use = request
                .params
                .get("single_use")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let tags: Vec<String> = request
                .params
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let issued = admin_create_auth_key(
                &daemon.state_dir,
                &coord_addr,
                expires_unix,
                single_use,
                &tags,
            )
            .await
            .map_err(|error| format!("{error:#}"))?;
            Ok(serde_json::json!({
                "auth_key": issued.plaintext,
                "key_id": issued.key_id,
            }))
        }
        "authkey_revoke" => {
            let coord_addr = daemon_coord_addr(&daemon)?;
            let key_id = request
                .params
                .get("key_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "缺少 key_id".to_string())?
                .to_string();
            admin_revoke_auth_key(&daemon.state_dir, &coord_addr, &key_id)
                .await
                .map_err(|error| format!("{error:#}"))?;
            Ok(serde_json::json!({}))
        }
        "node_list" => {
            let coord_addr = daemon_coord_addr(&daemon)?;
            let nodes = list_nodes(&daemon.state_dir, &coord_addr)
                .await
                .map_err(|error| format!("{error:#}"))?;
            serde_json::to_value(nodes).map_err(|e| e.to_string())
        }
        "node_rename" => {
            let coord_addr = daemon_coord_addr(&daemon)?;
            let node_id = request
                .params
                .get("node_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "缺少 node_id".to_string())?
                .to_string();
            let new_name = request
                .params
                .get("new_name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "缺少 new_name".to_string())?
                .to_string();
            let name = rename_node(&daemon.state_dir, &coord_addr, &node_id, &new_name)
                .await
                .map_err(|error| format!("{error:#}"))?;
            Ok(serde_json::json!({ "name": name }))
        }
        "node_delete" => {
            let coord_addr = daemon_coord_addr(&daemon)?;
            let node_id = request
                .params
                .get("node_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "缺少 node_id".to_string())?
                .to_string();
            delete_node(&daemon.state_dir, &coord_addr, &node_id)
                .await
                .map_err(|error| format!("{error:#}"))?;
            Ok(serde_json::json!({}))
        }
        "node_revoke" => {
            let coord_addr = daemon_coord_addr(&daemon)?;
            let node_id = request
                .params
                .get("node_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "缺少 node_id".to_string())?
                .to_string();
            revoke_node(&daemon.state_dir, &coord_addr, &node_id)
                .await
                .map_err(|error| format!("{error:#}"))?;
            Ok(serde_json::json!({}))
        }
        "login_poll" => {
            let progress = daemon.login.lock().expect("login poisoned").clone();
            let value = serde_json::to_value(&progress).map_err(|e| e.to_string())?;
            match (&progress, daemon.registration_info()) {
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

/// Policy / Admin 管理 rpc 需要 hzd 已注册（拿注册时记下的 Coordination Server 地址）。
fn daemon_coord_addr(daemon: &Daemon) -> Result<String, String> {
    daemon
        .coord_addr
        .lock()
        .expect("coord addr poisoned")
        .clone()
        .filter(|addr| !addr.is_empty())
        .ok_or_else(|| "hzd 尚未注册，无法执行管理操作（先 hz up）".to_string())
}

/// `hz ping`（FR-12）：朝对端 Node Address 发应用层探针，测往返时延，
/// 并报告此刻的路径形态与在用 Endpoint。冷握手的首个探针可能被
/// WireGuard 握手吃掉，最多重试 3 次。
async fn ping_peer(daemon: &Arc<Daemon>, target: &str) -> Result<Value, String> {
    let engine = daemon
        .engine
        .lock()
        .expect("engine poisoned")
        .clone()
        .ok_or_else(|| "数据面未运行（先 hz up 注册本机）".to_string())?;
    let own = daemon
        .registration
        .lock()
        .expect("registration poisoned")
        .info()
        .ok_or_else(|| "本机未注册".to_string())?;
    let peer = daemon
        .map_cache
        .snapshot()
        .into_iter()
        .find(|node| node.node_id == target || node.name == target)
        .ok_or_else(|| format!("Network Map 中找不到对端 {target}"))?;
    if peer.node_id == own.node_id {
        return Err("不能 ping 本机".to_string());
    }
    let own_v4: std::net::Ipv4Addr = own
        .ipv4
        .parse()
        .map_err(|_| format!("本机 Node Address 无效：{}", own.ipv4))?;
    let peer_v4: std::net::Ipv4Addr = peer
        .ipv4
        .parse()
        .map_err(|_| format!("对端 Node Address 无效：{}", peer.ipv4))?;

    let mut rtt = None;
    for _ in 0..3 {
        use rand_core::RngCore;
        let nonce = rand_core::OsRng.next_u64();
        let done = daemon.probes.spawn(nonce);
        let sent = std::time::Instant::now();
        engine
            .send_ip_packet(&ping::build(own_v4, peer_v4, false, nonce))
            .await;
        if tokio::time::timeout(Duration::from_secs(3), done)
            .await
            .is_ok_and(|result| result.is_ok())
        {
            rtt = Some(sent.elapsed());
            break;
        }
    }
    let rtt = rtt.ok_or_else(|| format!("{} 无应答（3 次尝试）", peer.name))?;
    let report = engine
        .peer_reports()
        .into_iter()
        .find(|report| report.node_id == peer.node_id);
    let (path, endpoint) = match report {
        Some(report) if !report.use_relay => ("direct", report.endpoint.map(|e| e.to_string())),
        Some(_) => ("relay", None),
        None => ("relay", None),
    };
    Ok(serde_json::json!({
        "name": peer.name,
        "rtt_ms": rtt.as_secs_f64() * 1000.0,
        "path": path,
        "endpoint": endpoint,
    }))
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
    *daemon.registration.lock().expect("registration poisoned") = Session::Registered(info.clone());
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
/// staged_secret 是重新登录暂存的新 Node Key：只有登录完成才提交（落盘 +
/// 换引擎私钥 + 重放对账），失败路径不碰旧密钥。
fn spawn_login_poller(
    daemon: Arc<Daemon>,
    keys: Arc<KeyStore>,
    started: StartedLogin,
    coord_addr: String,
    staged_secret: Option<NodeStaticSecret>,
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
                    if let Some(secret) = staged_secret {
                        if let Err(error) = keys.commit_node_rotation(&daemon.state_dir, &secret) {
                            let error = format!("Node Key 轮换落盘失败：{error:#}");
                            tracing::error!(%error, "commit node key rotation failed");
                            *daemon.login.lock().expect("login poisoned") =
                                LoginProgress::Failed { error };
                            return;
                        }
                        if let Some(engine) = daemon.engine.lock().expect("engine poisoned").clone()
                        {
                            engine.rotate_own_key(secret);
                            let decisions =
                                daemon.use_relay.lock().expect("use_relay poisoned").clone();
                            apply_cache_to_engine(
                                &daemon.map_cache,
                                &engine,
                                &info.node_id,
                                &decisions,
                            );
                        }
                    }
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
    // 过期态不可能与任何对端通信；缓存留在盘上，status 不再展示对端。
    if daemon.is_expired() {
        return Vec::new();
    }
    let own_node_id = daemon.registration_info().map(|info| info.node_id);
    let ages = daemon
        .engine
        .lock()
        .expect("engine poisoned")
        .as_ref()
        .map(|engine| engine.handshake_ages())
        .unwrap_or_default();
    let reports: HashMap<String, PeerReport> = daemon
        .engine
        .lock()
        .expect("engine poisoned")
        .as_ref()
        .map(|engine| {
            engine
                .peer_reports()
                .into_iter()
                .map(|report| (report.node_id.clone(), report))
                .collect()
        })
        .unwrap_or_default();
    daemon
        .map_cache
        .snapshot()
        .into_iter()
        .filter(|node| own_node_id.as_deref() != Some(node.node_id.as_str()))
        .map(|node| {
            let report = reports.get(&node.node_id);
            MapPeer {
                handshake_secs: ages
                    .get(&node.node_id)
                    .and_then(|age| age.map(Duration::from))
                    .map(|age| age.as_secs()),
                path: report.map(|report| {
                    if report.use_relay {
                        "relay".to_string()
                    } else {
                        "direct".to_string()
                    }
                }),
                endpoint: report
                    .and_then(|report| report.endpoint)
                    .map(|endpoint| endpoint.to_string()),
                name: node.name,
                ipv4: node.ipv4,
                ipv6: node.ipv6,
                endpoints: node.endpoints,
            }
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
    // HZD_BIND_EGRESS=0：开发/测试拓扑的对端在回环上，无法从物理出口网卡
    // 到达（SO_BINDTODEVICE 挡掉 127.0.0.1 收发），显式要求下才跳过绑定。
    let bind_to_egress = std::env::var("HZD_BIND_EGRESS").ok().as_deref() != Some("0");
    if !bind_to_egress {
        tracing::warn!("egress binding disabled by HZD_BIND_EGRESS=0");
    }
    let engine = Arc::new(SocketEngine::bind_with(keys.node(), port, bind_to_egress).await?);
    let endpoint = lan_endpoint(coord_addr, engine.local_addr().port()).await?;
    tracing::info!(%endpoint, "reporting lan endpoint");

    if let Ok(relay_addr) = std::env::var("HZD_RELAY_ADDR") {
        if !relay_addr.is_empty() {
            spawn_relay_supervisor(
                &engine,
                keys,
                &info.node_id,
                &relay_addr,
                daemon.egress_epoch.clone(),
            );
        }
    }

    spawn_tun_bridge(
        &engine,
        info,
        &daemon.map_cache,
        &daemon.policy_gate,
        daemon.probes.clone(),
    );
    spawn_map_task(
        daemon.clone(),
        engine.clone(),
        info.node_id.clone(),
        endpoint.to_string(),
        coord_addr.to_string(),
        daemon.policy_gate.clone(),
    );
    // 段内 DNS 应答地址：注册响应携带（#20）；旧服务端回落规格 A2 固定值。
    let dns_v4 = info
        .dns_v4
        .as_deref()
        .and_then(|text| text.parse().ok())
        .unwrap_or(hz_core::dns::DNS_BIND_V4);
    if let Err(error) = dns::spawn(daemon.map_cache.clone(), dns_v4).await {
        tracing::warn!(%error, "dns responder unavailable");
    }
    spawn_endpoint_collector(
        daemon.state_dir.clone(),
        daemon.own_endpoints.clone(),
        daemon.punch.clone(),
        engine.clone(),
        coord_addr.to_string(),
    );
    spawn_net_recovery(daemon, engine.clone(), coord_addr);
    spawn_path_task(
        daemon.map_cache.clone(),
        daemon.map_signal.clone(),
        daemon.own_endpoints.clone(),
        daemon.use_relay.clone(),
        daemon.punch.clone(),
        engine.clone(),
        keys.clone(),
        &info.node_id,
    );
    #[cfg(target_os = "macos")]
    spawn_egress_watch();
    *daemon.engine.lock().expect("engine poisoned") = Some(engine);
    Ok(())
}

/// 生效 IPv4 段（FR-4）：注册响应携带的值为权威（与坐标分配一致），
/// HZD_V4_CIDR 仅作显式覆盖并在与注册值失配时告警，避免静默双源漂移。
fn effective_v4_cidr(info: &RegisteredInfo, env_override: Option<String>) -> String {
    match (
        info.network_cidr.as_deref(),
        env_override.filter(|v| !v.is_empty()),
    ) {
        (Some(from_coord), Some(override_)) => {
            if override_ != from_coord {
                tracing::warn!(
                    from_coord,
                    override_,
                    "HZD_V4_CIDR 与服务端生效段不一致，采用环境变量覆盖（路由将不匹配分配段）"
                );
            }
            override_
        }
        (Some(from_coord), None) => from_coord.to_string(),
        (None, Some(override_)) => override_,
        (None, None) => DEFAULT_V4_CIDR.to_string(),
    }
}

#[cfg(test)]
mod effective_v4_cidr_tests {
    use super::*;

    fn info(cidr: Option<&str>) -> RegisteredInfo {
        RegisteredInfo {
            node_id: "n".into(),
            name: "n".into(),
            ipv4: "10.44.0.1".into(),
            ipv6: "fd::1".into(),
            tags: vec![],
            owner_user: None,
            expires_at_unix: None,
            network_cidr: cidr.map(str::to_string),
            dns_v4: None,
        }
    }

    #[test]
    fn registration_value_is_authoritative() {
        assert_eq!(
            effective_v4_cidr(&info(Some("10.44.0.0/24")), None),
            "10.44.0.0/24"
        );
    }

    #[test]
    fn explicit_env_overrides_with_mismatch_logged() {
        assert_eq!(
            effective_v4_cidr(&info(Some("10.44.0.0/24")), Some("10.55.0.0/16".into())),
            "10.55.0.0/16",
            "显式环境变量覆盖优先（失配已在日志告警）"
        );
    }

    #[test]
    fn legacy_registration_falls_back_to_env_then_default() {
        assert_eq!(
            effective_v4_cidr(&info(None), Some("10.55.0.0/16".into())),
            "10.55.0.0/16"
        );
        assert_eq!(effective_v4_cidr(&info(None), None), DEFAULT_V4_CIDR);
    }
}

/// macOS 出口监视的守护进程侧消费：保住监视任务的生命周期并留痕。
/// 已有长连 socket 的重绑随 #9 的跨平台监视合流。
#[cfg(target_os = "macos")]
fn spawn_egress_watch() {
    tokio::spawn(async move {
        let mut events = hz_core::netwatch_mac::spawn_watcher();
        while let Some(event) = events.recv().await {
            tracing::info!(
                ?event,
                "egress changed; sockets created from now on bind the new egress"
            );
        }
    });
}
/// Relay 传输监督（#7 单连 → #8 断线重连 → #9 出口变化强拔）：连上后挂到
/// 引擎；流断开按退避重连；物理出口变化（egress_epoch）不等 TCP 死亡立刻
/// 重拨。CA 路径（HZD_RELAY_CA_PATH）指向私有 CA 的 PEM。
fn spawn_relay_supervisor(
    engine: &Arc<SocketEngine>,
    keys: &Arc<KeyStore>,
    node_id: &str,
    relay_addr: &str,
    egress_epoch: EgressEpoch,
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
            // 先记下当前代数再连接：连接期间发生的出口变化也不会漏。
            let mut epoch = egress_epoch.receiver();
            epoch.borrow_and_update();
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
                    let mut forced = false;
                    tokio::select! {
                        _ = client.wait_closed() => {
                            tracing::warn!(%relay_addr, "relay transport down, reconnecting");
                        }
                        _ = epoch.changed() => {
                            forced = true;
                            tracing::info!(%relay_addr, "egress changed, forcing relay redial");
                        }
                    }
                    if forced {
                        continue;
                    }
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
/// 推导（FR-8：STUN 与 Relay 同主机，UDP 3478）。地址可以是主机名或 IP；
/// SocketAddr::parse 只认 IP 字面量，主机名必须走 DNS（启动时一次阻塞解析，
/// 与 coord_probe_target 同一先例），解析失败显式告警而不是静默禁用 STUN。
fn stun_server_addr() -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    let raw = std::env::var("HZD_STUN_ADDR").ok().or_else(|| {
        let relay = std::env::var("HZD_RELAY_ADDR").ok()?;
        let host_port = relay
            .rsplit_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(&relay);
        let host = host_port
            .rsplit_once(':')
            .map(|(host, _)| host)
            .unwrap_or(host_port);
        Some(format!("{host}:3478"))
    })?;
    match raw.to_socket_addrs() {
        Ok(mut addrs) => addrs.next(),
        Err(error) => {
            tracing::warn!(%raw, %error, "STUN 服务器地址解析失败");
            None
        }
    }
}

/// Endpoint 收集与上报（FR-8）：周期性收集 Lan/STUN/V6，ReportEndpoints 落库，
/// 结果同时存进共享槽供打洞信令取本机候选；打洞累计计数随上报携带（FR-12）。
/// 收集动作本身抽成 [`collect_and_report`]，网络变化恢复序列即时复用。
fn spawn_endpoint_collector(
    state_dir: PathBuf,
    own_slot: Arc<StdMutex<Vec<DiscoveredEndpoint>>>,
    punch: Arc<StdMutex<PunchCounters>>,
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
            collect_and_report(
                &state_dir,
                &own_slot,
                &punch,
                &engine,
                &coord_addr,
                stun_server,
            )
            .await;
        }
    });
}

/// 收集一轮本机 Endpoint 并上报（周期收集与网络变化恢复共用）：
/// STUN 查询走引擎共享 socket（重绑后自动落在新出口上），结果连同
/// Lan/V6 候选写入共享槽并 ReportEndpoints 给 Coordination Server。
async fn collect_and_report(
    state_dir: &Path,
    own_slot: &Arc<StdMutex<Vec<DiscoveredEndpoint>>>,
    punch: &Arc<StdMutex<PunchCounters>>,
    engine: &Arc<SocketEngine>,
    coord_addr: &str,
    stun_server: Option<SocketAddr>,
) {
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
    let counters = *punch.lock().expect("punch counters poisoned");
    if let Err(error) = report_endpoints(state_dir, &found, coord_addr, Some(counters)).await {
        tracing::warn!(%error, "endpoint report to coord failed");
    }
}

/// 网络变化恢复序列（FR-8 本机网络变化后自动恢复）。netwatch 的去抖事件
/// 到来时重算快照：确有变化（或休眠唤醒）才执行——重绑 UDP socket 到新
/// 物理出口 → 作废直连记账 → 即时 STUN + ReportEndpoints（对端拿到新公网
/// 映射）→ 递增出口代数（Map 订阅与 Relay 长连接立刻重拨）→ 唤醒路径任务
/// 重启打洞。全部动作幂等，事件风暴下重复执行也收敛到同一终态。
/// 非 Linux 上 netwatch 无事件（#16），本任务随即退出。
fn spawn_net_recovery(daemon: &Arc<Daemon>, engine: Arc<SocketEngine>, coord_addr: &str) {
    let state_dir = daemon.state_dir.clone();
    let own_slot = daemon.own_endpoints.clone();
    let punch = daemon.punch.clone();
    let map_signal = daemon.map_signal.clone();
    let egress_epoch = daemon.egress_epoch.clone();
    let coord_addr = coord_addr.to_string();
    tokio::spawn(async move {
        let mut events = netwatch::spawn();
        let stun_server = stun_server_addr();
        let mut handled = netwatch::egress_snapshot();
        while let Some(event) = events.recv().await {
            let current = netwatch::egress_snapshot();
            let wake = matches!(event, NetEvent::ClockJump);
            if !wake && !netwatch::snapshot_changed(&handled, &current) {
                tracing::debug!(?event, "net event without egress change, ignoring");
                continue;
            }
            handled = current.clone();
            tracing::info!(?event, egress = ?current.iface, "network change, recovering");
            if let Some(egress) = current.iface.clone() {
                match engine.rebind(&egress).await {
                    Ok(outcome) => tracing::info!(?outcome, %egress, "udp socket rebound"),
                    Err(error) => tracing::warn!(%egress, %error, "udp socket rebind failed"),
                }
            }
            engine.reset_direct_rx();
            // 换网瞬间路由可能尚未收敛：STUN 限次重试，给出口几秒钟。
            for round in 0..3 {
                collect_and_report(
                    &state_dir,
                    &own_slot,
                    &punch,
                    &engine,
                    &coord_addr,
                    stun_server,
                )
                .await;
                let stun_reached = stun_server.is_none()
                    || own_slot
                        .lock()
                        .expect("own endpoints poisoned")
                        .iter()
                        .any(|found| found.kind == hz_core::endpoint::EndpointKind::Stun);
                if stun_reached || round == 2 {
                    break;
                }
                tracing::debug!(
                    round,
                    "stun not reachable yet, retrying after egress change"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            egress_epoch.bump();
            map_signal.notify_one();
        }
    });
}

/// 路径管理任务（FR-8）：每秒推进状态机 + Map 变化、打洞信令即时唤醒。
/// 产出的事件在这里执行：切引擎传输开关（带日志）、发打洞握手、经 Relay
/// 收发 PunchOffer/PunchAck。HZD_FORCE_RELAY=1 时全部对端钉在 Relay。
#[allow(clippy::too_many_arguments)]
fn spawn_path_task(
    cache: Arc<NetworkMapCache>,
    map_signal: Arc<tokio::sync::Notify>,
    own_slot: Arc<StdMutex<Vec<DiscoveredEndpoint>>>,
    use_relay_slot: Arc<StdMutex<HashMap<String, bool>>>,
    punch_slot: Arc<StdMutex<PunchCounters>>,
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
                apply_path_event(
                    &engine,
                    &own_slot,
                    &use_relay_slot,
                    &punch_slot,
                    &keys,
                    &peers,
                    event,
                )
                .await;
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
    punch_slot: &Arc<StdMutex<PunchCounters>>,
    keys: &Arc<KeyStore>,
    peers: &[PeerView],
    event: PathEvent,
) {
    let forced = force_relay();
    match event {
        PathEvent::SetUseRelay { node_id, use_relay } => {
            if !use_relay {
                // 打洞成功一次（Relayed → Direct 的升级，FR-12 成功率分子）。
                punch_slot
                    .lock()
                    .expect("punch counters poisoned")
                    .successes += 1;
            }
            let use_relay = (use_relay || forced) && relay_transport_configured();
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
            // 一轮打洞（Offer + 握手并发，FR-12 成功率分母）。
            punch_slot.lock().expect("punch counters poisoned").attempts += 1;
            let Some(relay) = engine.relay_client() else {
                tracing::debug!(%node_id, "punch offer skipped: no relay transport");
                return;
            };
            let Some(peer) = peers.iter().find(|peer| peer.endpoints.node_id == node_id) else {
                return;
            };
            let codec = PunchCodec::new(&keys.node(), &peer.node_key);
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
            let codec = PunchCodec::new(&keys.node(), &peer.node_key);
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
        let codec = PunchCodec::new(&keys.node(), &peer.node_key);
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

/// TUN 读到的包进引擎，引擎解密的包写回 TUN；写入前依次过 ping 探针拦截
/// （`hz ping` 的应答在这里被消化）与入站 Policy 闸（A1）：源地址 → Map 里
/// 的对端身份（归属 User + Tag），目标端口取自 TCP/UDP 头，规则之外默认
/// 拒绝并计数。TUN 不可用时只保留引擎收发与探针拦截（无写入路径即无过滤点）。
fn spawn_tun_bridge(
    engine: &Arc<SocketEngine>,
    info: &RegisteredInfo,
    cache: &Arc<NetworkMapCache>,
    gate: &Arc<InboundGate>,
    probes: Arc<ping::Probes>,
) {
    let (to_tunnel_tx, to_tunnel_rx) = mpsc::channel::<Vec<u8>>(256);
    tokio::spawn({
        let engine = engine.clone();
        async move {
            if let Err(error) = engine.run(to_tunnel_tx).await {
                tracing::error!(%error, "wireguard engine loop exited");
            }
        }
    });
    let own_v4: Option<std::net::Ipv4Addr> = info.ipv4.parse().ok();

    #[cfg(any(target_os = "linux", target_os = "macos"))]
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
                spawn_tunnel_drain(engine.clone(), probes, own_v4, to_tunnel_rx);
                return;
            }
        };
        let tun_config = TunConfig {
            ipv4,
            ipv6,
            v4_cidr: effective_v4_cidr(info, std::env::var("HZD_V4_CIDR").ok()),
        };
        match Tun::setup(&tun_config) {
            Ok(tun) => {
                let device = tun.device();
                tokio::spawn({
                    let device = device.clone();
                    let cache = cache.clone();
                    let gate = gate.clone();
                    let engine = engine.clone();
                    let probes = probes.clone();
                    let own_v4 = own_v4.expect("地址解析成功才走到 TUN 分支，own_v4 必然存在");
                    async move {
                        // 源地址 → 对端身份索引，随 Map 版本重建（对账口径与引擎一致）。
                        let mut index_version = u64::MAX;
                        let mut peer_index: HashMap<IpAddr, (String, Option<String>, Vec<String>)> =
                            HashMap::new();
                        while let Some(packet) = to_tunnel_rx.recv().await {
                            // 探针在 Policy 闸之前：探针端口是 hzd 自身控制面，且对端
                            // 能把包送到本机即已在本机 Map 里；hz ping 才反映路径本身。
                            if ping::intercept(&engine, &probes, own_v4, &packet).await {
                                continue;
                            }
                            if cache.version() != index_version {
                                index_version = cache.version();
                                peer_index = cache
                                    .snapshot()
                                    .into_iter()
                                    .filter_map(|node| {
                                        let v4: Option<IpAddr> = node.ipv4.parse().ok();
                                        let v6: Option<IpAddr> = node.ipv6.parse().ok();
                                        let facts =
                                            (node.node_id.clone(), node.owner_user, node.tags);
                                        v4.into_iter()
                                            .chain(v6)
                                            .map(move |addr| (addr, facts.clone()))
                                            .next()
                                    })
                                    .collect();
                            }
                            let class = hz_core::policy::classify_packet(&packet);
                            let peer = class_src(&class).and_then(|src| peer_index.get(&src));
                            let admitted = gate.admit(
                                class,
                                peer.map(|(node_id, owner, tags)| hz_core::policy::PeerFacts {
                                    node_id,
                                    owner_user: owner.as_deref(),
                                    tags: tags.as_slice(),
                                }),
                            );
                            if !admitted {
                                continue;
                            }
                            if let Err(error) = device.send(&packet).await {
                                tracing::error!(%error, "tun write failed");
                                break;
                            }
                        }
                    }
                });
                let engine = engine.clone();
                let cache = cache.clone();
                let gate = gate.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65_535];
                    // 出方向流登记（回包放行依据）与入方向共用对端索引口径。
                    let mut index_version = u64::MAX;
                    let mut peer_index: HashMap<IpAddr, String> = HashMap::new();
                    loop {
                        match device.recv(&mut buf).await {
                            Ok(len) => {
                                let packet = &buf[..len];
                                let class = hz_core::policy::classify_packet(packet);
                                if cache.version() != index_version {
                                    index_version = cache.version();
                                    peer_index = cache
                                        .snapshot()
                                        .into_iter()
                                        .filter_map(|node| {
                                            let v4: Option<IpAddr> = node.ipv4.parse().ok();
                                            let v6: Option<IpAddr> = node.ipv6.parse().ok();
                                            v4.into_iter()
                                                .chain(v6)
                                                .map(move |addr| (addr, node.node_id.clone()))
                                                .next()
                                        })
                                        .collect();
                                }
                                let peer = class_dst(&class).and_then(|dst| peer_index.get(&dst));
                                gate.note_outbound(class, peer.map(String::as_str));
                                engine.send_ip_packet(packet).await
                            }
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
                spawn_tunnel_drain(engine.clone(), probes, own_v4, to_tunnel_rx);
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (cache, gate);
        spawn_tunnel_drain(engine.clone(), probes, own_v4, to_tunnel_rx);
    }
}

/// 入方向：取包的源地址（对端身份索引的键）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn class_src(class: &hz_core::policy::PacketClass) -> Option<IpAddr> {
    match class {
        hz_core::policy::PacketClass::Flow { src, .. }
        | hz_core::policy::PacketClass::Other { src } => Some(*src),
        hz_core::policy::PacketClass::Malformed => None,
    }
}

/// 出方向：取包的目的地址（对端索引的键）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn class_dst(class: &hz_core::policy::PacketClass) -> Option<IpAddr> {
    match class {
        hz_core::policy::PacketClass::Flow { dst, .. } => Some(*dst),
        _ => None,
    }
}

/// 无 TUN 时丢弃解密包（探针先拦截），防 channel 满背压拖住引擎循环。
fn spawn_tunnel_drain(
    engine: Arc<SocketEngine>,
    probes: Arc<ping::Probes>,
    own_v4: Option<std::net::Ipv4Addr>,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            if let Some(v4) = own_v4 {
                if ping::intercept(&engine, &probes, v4, &packet).await {
                    continue;
                }
            }
        }
    });
}

/// 从 Map 消失后向服务端问一次，区分吊销与到期（removed 差量不携带原因，
/// 两种结局共享 Expired 会话态）。吊销态决定 `hz status` 文案：已吊销
/// 不能靠重新登录恢复，重新加入只能以全新身份注册。
async fn note_revocation(
    daemon: &Arc<Daemon>,
    state_dir: &std::path::Path,
    endpoint: &str,
    coord_addr: &str,
) {
    match open_network_map_stream(state_dir, vec![endpoint.to_string()], coord_addr).await {
        Err(error) if error.to_string().contains("已吊销") => {
            tracing::warn!(%error, "node revoked by admin");
            *daemon.revoked.lock().expect("revoked poisoned") = true;
        }
        _ => {}
    }
}

/// Network Map 消费任务（FR-6）：启动即用本地缓存配置数据面（Coordination
/// Server 不可达也照常），然后循环 订阅 → 消费差量/全量 → 断线退避重连。
/// 每次重连都重新走挑战认证并重报 Endpoint（服务端在流打开时落库）；Endpoint
/// 取共享槽里的最新收集结果（出口变化后重拨不会把启动时的旧地址写回去），
/// 槽为空才退回启动时探测的 LAN Endpoint。
/// Map 有实际变化时唤醒路径任务（打洞轮次紧跟对端 Endpoint 更新）。
/// 到期反应（FR-3）：自己出现在 removed 差量、或订阅被服务端以「已过期」
/// 拒绝时，转入 Expired 并拆掉对端，随后驻留轮询——不退避重连浪费连接，
/// 重新登录完成后状态翻回 Registered，本任务自动恢复订阅。
/// 物理出口变化（egress_epoch）不等 TCP 死亡立刻强制重拨（FR-8 恢复）。
fn spawn_map_task(
    daemon: Arc<Daemon>,
    engine: Arc<SocketEngine>,
    own_node_id: String,
    boot_endpoint: String,
    coord_addr: String,
    policy_gate: Arc<InboundGate>,
) {
    let state_dir = daemon.state_dir.clone();
    let cache = daemon.map_cache.clone();
    let map_signal = daemon.map_signal.clone();
    let use_relay = daemon.use_relay.clone();
    let own_slot = daemon.own_endpoints.clone();
    let egress_epoch = daemon.egress_epoch.clone();
    tokio::spawn(async move {
        let decisions = use_relay.lock().expect("use_relay poisoned").clone();
        apply_cache_to_engine(&cache, &engine, &own_node_id, &decisions);
        let mut backoff = BACKOFF_START;
        loop {
            if daemon.is_expired() {
                tokio::time::sleep(EXPIRED_POLL).await;
                continue;
            }
            // 先记代数再连接：连接期间发生的出口变化不会漏。
            let mut epoch = egress_epoch.receiver();
            epoch.borrow_and_update();
            let mut forced = false;
            let endpoints = endpoint_strings(&own_slot, &boot_endpoint);
            match open_network_map_stream(&state_dir, endpoints, &coord_addr).await {
                Ok(mut stream) => {
                    backoff = BACKOFF_START;
                    tracing::info!(%coord_addr, "network map stream opened");
                    loop {
                        let message = tokio::select! {
                            message = stream.message() => match message {
                                Ok(Some(message)) => message,
                                Ok(None) => {
                                    tracing::warn!("network map stream closed by server");
                                    break;
                                }
                                Err(error) => {
                                    tracing::warn!(%error, "network map stream error");
                                    break;
                                }
                            },
                            _ = epoch.changed() => {
                                forced = true;
                                tracing::info!("egress changed, forcing map stream redial");
                                break;
                            }
                        };
                        if let Some(view) = message.policy.as_ref() {
                            policy_gate.update(InboundPolicyView::from_proto(view));
                        }
                        if let Some(kind) = message.kind {
                            let removed_own = match &kind {
                                hz_proto::network_map_message::Kind::Delta(delta) => {
                                    delta.removed_node_ids.iter().any(|id| id == &own_node_id)
                                }
                                hz_proto::network_map_message::Kind::Full(_) => false,
                            };
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
                            if removed_own {
                                daemon.mark_expired(&engine);
                                let probe_endpoint = endpoint_strings(&own_slot, &boot_endpoint)
                                    .into_iter()
                                    .next()
                                    .unwrap_or_default();
                                note_revocation(&daemon, &state_dir, &probe_endpoint, &coord_addr)
                                    .await;
                                break;
                            }
                        }
                    }
                }
                Err(error) => {
                    if error.to_string().contains("已过期") {
                        tracing::warn!(%error, "coord rejected map subscription: node expired");
                        daemon.mark_expired(&engine);
                        backoff = BACKOFF_START;
                    } else if error.to_string().contains("已吊销") {
                        tracing::warn!(%error, "coord rejected map subscription: node revoked");
                        daemon.mark_expired(&engine);
                        *daemon.revoked.lock().expect("revoked poisoned") = true;
                        backoff = BACKOFF_START;
                    } else {
                        tracing::warn!(%error, "network map subscription failed");
                    }
                }
            }
            if !daemon.is_expired() && !forced {
                tokio::time::sleep(jittered(backoff)).await;
                backoff = backoff.saturating_mul(2).min(BACKOFF_CAP);
            }
        }
    });
}

/// Map 订阅随流携带的 Endpoint 字符串：共享槽的最新收集结果；空槽（收集
/// 尚未跑过）退回启动时探测的 LAN Endpoint。服务端在流打开时整体覆盖
/// 落库，必须给最新值，否则出口变化后的重拨会把旧地址写回去。
fn endpoint_strings(
    own_slot: &Arc<StdMutex<Vec<DiscoveredEndpoint>>>,
    boot_endpoint: &str,
) -> Vec<String> {
    let collected = own_slot.lock().expect("own endpoints poisoned").clone();
    if collected.is_empty() {
        return vec![boot_endpoint.to_string()];
    }
    collected
        .into_iter()
        .map(|found| found.addr.to_string())
        .collect()
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
        // 没配 Relay 传输时直连是唯一存在的路径，不能默认进黑洞。
        // HZD_FORCE_RELAY=1 在事件应用处把一切直连决定压回 Relay。
        use_relay: use_relay
            .get(&node.node_id)
            .copied()
            .unwrap_or_else(relay_transport_configured),
    })
}

fn force_relay() -> bool {
    std::env::var("HZD_FORCE_RELAY").ok().as_deref() == Some("1")
}

/// 是否配置了 Relay 传输（数据面据此决定是否允许把对端钉在 Relay）。
/// 没配 Relay 时选 Relay 是把引擎流量（重握手、保活、数据）路由进不存在
/// 的通道——全部被静默丢弃，数据面只剩按退避节奏的打洞包，握手在慢
/// 机器上永远完不成；此时对端必须直连（有候选 Endpoint 就朝它们发）。
fn relay_transport_configured() -> bool {
    std::env::var("HZD_RELAY_ADDR").is_ok_and(|addr| !addr.is_empty())
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
