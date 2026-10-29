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
    admin_create_invite, admin_list_invites, admin_revoke_auth_key, admin_revoke_invite,
    begin_interactive_login, delete_node, list_nodes, local_hostname, open_network_map_stream,
    policy_get, policy_push, policy_rollback, poll_login_status, register_with_auth_key,
    rename_node, report_endpoints, revoke_node,
};
use hz_core::endpoint::{self, DiscoveredEndpoint};
use hz_core::health::{HealthSnapshot, RelayedPeerNote, nat_kind, relay_reason};
use hz_core::ipc::{self, Handler};
use hz_core::keys::{KeyStore, NodeStaticSecret};
use hz_core::map::{MapNode, NetworkMapCache};
use hz_core::netcheck::{self, EndpointNote, NetcheckReport, StunReport, UdpProbe, UdpReport};
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

pub mod diagnostics;
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

/// Desired State（#81 / MC-1）：User 对本机数据面的期望，`up` / `down`。
/// 持久化在 state_dir 的 desired_state.json；缺省（旧安装升级、文件损坏）
/// 视为 `up`——不因读写问题改变旧行为。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum DesiredState {
    Up,
    Down,
}

impl DesiredState {
    fn as_str(self) -> &'static str {
        match self {
            DesiredState::Up => "up",
            DesiredState::Down => "down",
        }
    }
}

const DESIRED_STATE_FILE: &str = "desired_state.json";

fn load_desired_state(state_dir: &Path) -> DesiredState {
    let text = std::fs::read_to_string(state_dir.join(DESIRED_STATE_FILE)).unwrap_or_default();
    match serde_json::from_str::<DesiredStateWrapper>(&text) {
        Ok(wrapper) => wrapper.state,
        // 缺失 / 损坏 / 旧版本没有该文件：一律按 up（缺省语义）。
        Err(_) => DesiredState::Up,
    }
}

fn save_desired_state(state_dir: &Path, state: DesiredState) -> anyhow::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let path = state_dir.join(DESIRED_STATE_FILE);
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
        file.write_all(serde_json::to_string_pretty(&DesiredStateWrapper { state })?.as_bytes())?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DesiredStateWrapper {
    state: DesiredState,
}

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

/// 运行中路由自检的周期（#24：被删除/被占用的 HzNet 路由 10 秒内恢复）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
const ROUTE_CHECK_INTERVAL: Duration = Duration::from_secs(3);

/// 最近一次运行中路由修复（#24），供 `hz status` 汇报（#25）。
static LAST_ROUTE_REPAIR: StdMutex<Option<RouteRepairNote>> = StdMutex::new(None);

#[derive(Debug, Clone, serde::Serialize)]
struct RouteRepairNote {
    /// Unix 秒。
    at: u64,
    cidr: String,
    /// 修复前的状态：被删除或被某网卡占用。
    previous: hz_core::tun::RouteHealth,
}

/// 周期（及物理出口变化时）检查 HzNet 路由，被删除或被其他网卡的同前缀
/// 路由占用时重新安装（#24）。
/// 路由正常时只读不写、不打日志；自检本身出错只在错误变化时告警一次。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn spawn_route_guard(
    tun: Arc<Tun>,
    mut egress: tokio::sync::watch::Receiver<u64>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(ROUTE_CHECK_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await; // 跳过立即的首跳：setup 刚装好路由
        let mut egress_open = true;
        let mut last_error: Option<String> = None;
        loop {
            // 周期检查；物理出口变化（网络变化恢复递增出口代数）时立即检查。
            tokio::select! {
                _ = tick.tick() => {}
                changed = egress.changed(), if egress_open => {
                    egress_open = changed.is_ok();
                }
            }
            let tun = tun.clone();
            let outcome = tokio::task::spawn_blocking(move || tun.check_and_repair_routes()).await;
            match outcome {
                Ok(Ok(repairs)) => {
                    last_error = None;
                    for repair in repairs {
                        match &repair.previous {
                            hz_core::tun::RouteHealth::TakenBy(iface) => tracing::warn!(
                                cidr = %repair.cidr,
                                taken_by = %iface,
                                "HzNet 路由被其他网卡（{iface}）的同前缀路由占用，已夺回"
                            ),
                            _ => {
                                tracing::warn!(cidr = %repair.cidr, "HzNet 路由被删除，已重新安装")
                            }
                        }
                        *LAST_ROUTE_REPAIR.lock().expect("route repair poisoned") =
                            Some(RouteRepairNote {
                                at: hz_core::outer_dns::unix_now(),
                                cidr: repair.cidr,
                                previous: repair.previous,
                            });
                    }
                }
                Ok(Err(error)) => {
                    let text = error.to_string();
                    if last_error.as_deref() != Some(text.as_str()) {
                        tracing::warn!(error = %text, "HzNet 路由自检失败");
                        last_error = Some(text);
                    }
                }
                Err(error) => tracing::warn!(%error, "HzNet 路由自检任务异常"),
            }
        }
    })
}

/// 每个对端的打洞信令观察（Relay 原因判定的输入，规格 §4）：路径任务在
/// 发 Offer / 收 Ack 时记录，Health Report 生成时读取。
#[derive(Debug, Clone, Copy, Default)]
struct PunchObs {
    /// 本机最近一次发出 PunchOffer 的时刻。
    offer_at: Option<std::time::Instant>,
    /// 最近一次收到对端 PunchAck 的时刻（双方都朝候选出过洞）。
    ack_at: Option<std::time::Instant>,
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
    /// 每个对端最近一次打洞结果（`hz netcheck` 用）。
    punch_last: Arc<StdMutex<HashMap<String, String>>>,
    /// 每个对端的打洞信令观察（Relay 原因判定，#72）。
    punch_obs: Arc<StdMutex<HashMap<String, PunchObs>>>,
    /// 端口映射状态（#77）：netcheck 展示。
    portmap_status: Arc<StdMutex<hz_core::netcheck::PortMapNote>>,
    /// 端口映射成功时的候选 Endpoint（合并进 own_endpoints 一起上报）。
    portmap_endpoint: Arc<StdMutex<Option<DiscoveredEndpoint>>>,
    /// 等待中的 ping 探针（应答到达时唤醒）。
    probes: Arc<ping::Probes>,
    /// 本 Node 已被 Admin 吊销（区别于过期：重新登录救不回来）。
    /// 到期/吊销共享 Expired 会话态，此标记决定 `hz status` 的文案。
    revoked: StdMutex<bool>,
    /// 物理出口变化代数：长连接任务据此强制重拨（见类型注释）。
    egress_epoch: EgressEpoch,
    /// Desired State（#81）：up / down。
    desired_state: StdMutex<DesiredState>,
    /// 数据面监督句柄（#81）：down 时取消并等待全部数据面任务退出。
    dataplane: StdMutex<Option<DataplaneHandle>>,
}

/// start_dataplane 的可停机句柄：cancel 后监督任务 abort 全部数据面子任务。
struct DataplaneHandle {
    cancel: tokio::sync::watch::Sender<bool>,
    supervisor: tokio::task::JoinHandle<()>,
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
    let desired_state = load_desired_state(&state_dir);
    if desired_state == DesiredState::Down {
        tracing::info!("desired state is down; dataplane stays down until `hz up`");
    }
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
        punch_last: Arc::new(StdMutex::new(HashMap::new())),
        punch_obs: Arc::new(StdMutex::new(HashMap::new())),
        portmap_status: Arc::new(StdMutex::new(hz_core::netcheck::PortMapNote::default())),
        portmap_endpoint: Arc::new(StdMutex::new(None)),
        probes: Arc::new(ping::Probes::default()),
        revoked: StdMutex::new(false),
        egress_epoch: EgressEpoch::new(),
        desired_state: StdMutex::new(desired_state),
        dataplane: StdMutex::new(None),
    });

    // 开机即已注册且 Desired State 为 up：直接拉起数据面（#81：down 时保持
    // 断开，`hz up` 才恢复）；coord 地址取注册时记下的，其次环境变量。
    // 上次运行期间是否已过期不落盘：由 Map 订阅被拒（已过期）在线发现。
    let boot_info = daemon
        .registration_info()
        .filter(|_| desired_state == DesiredState::Up);
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
        "status" => status_value(&daemon).await,
        "ping" => {
            let target = request
                .params
                .get("node")
                .and_then(Value::as_str)
                .ok_or_else(|| "缺少 node 参数（Node Name 或 node id）".to_string())?;
            ping_peer(&daemon, target).await
        }
        "netcheck" => {
            let report = collect_netcheck(&daemon).await;
            serde_json::to_value(&report).map_err(|error| error.to_string())
        }
        "diagnostics" => {
            // #84：普通 User 出问题时导出一份脱敏诊断文件发给 Admin。
            let mut value = serde_json::json!({
                "status": status_value(&daemon).await?,
                "version": hz_core::version::node_version(),
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
            });
            value["netcheck"] =
                serde_json::to_value(collect_netcheck(&daemon).await).map_err(|e| e.to_string())?;
            let (tail, note) = diagnostics::collect_log_tail();
            value["log_tail"] = serde_json::json!(tail);
            if let Some(note) = note {
                value["log_note"] = serde_json::json!(note);
            }
            Ok(value)
        }
        "down" => {
            // #81：停数据面（断 Network Map 流、停止上报、尽拆 TUN/DNS 接入），
            // 保留注册与密钥；持久化 `down`，重启后保持断开。
            shutdown_dataplane(&daemon).await;
            *daemon.desired_state.lock().expect("desired state poisoned") = DesiredState::Down;
            save_desired_state(&daemon.state_dir, DesiredState::Down)
                .map_err(|error| format!("写入 Desired State 失败：{error:#}"))?;
            Ok(serde_json::json!({ "desired_state": "down" }))
        }
        "up" => {
            let registered = daemon
                .coord_addr
                .lock()
                .expect("coord addr poisoned")
                .clone();
            let coord_addr = up_coord_addr(
                request.params.get("coord_addr").and_then(|v| v.as_str()),
                registered.as_deref(),
                std::env::var("HZD_COORD_ADDR").ok().as_deref(),
            );

            // #81：已注册（未过期）时 up 只是恢复数据面并写 `up`——不重新
            // 注册、不轮换 Node Key、不换 Coordination Server（显式 --coord
            // 被忽略）。过期态仍走原注册路径，由 coord 拒绝并指向重新登录。
            let registered = daemon.registration_info().filter(|_| !daemon.is_expired());
            if let Some(info) = registered {
                *daemon.desired_state.lock().expect("desired state poisoned") = DesiredState::Up;
                save_desired_state(&daemon.state_dir, DesiredState::Up)
                    .map_err(|error| format!("写入 Desired State 失败：{error:#}"))?;
                if daemon.engine.lock().expect("engine poisoned").is_none() {
                    let coord_addr = daemon
                        .coord_addr
                        .lock()
                        .expect("coord addr poisoned")
                        .clone()
                        .filter(|addr| !addr.is_empty())
                        .unwrap_or(coord_addr);
                    if let Err(error) = start_dataplane(&daemon, &keys, &info, &coord_addr).await {
                        tracing::error!(%error, "dataplane startup failed after up");
                    }
                }
                return serde_json::to_value(info).map_err(|e| e.to_string());
            }

            let invite_code = request
                .params
                .get("invite_code")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            match request
                .params
                .get("auth_key")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or_else(|| invite_code.clone())
            {
                Some(auth_key) => {
                    // 邀请码与 Auth Key 共用同一通道：有 invite 时 auth_key 传空串，
                    // 服务端按 invite_code 字段优先走短码核销。
                    let auth_key = if invite_code.is_some() { "" } else { &auth_key };
                    let info = register_with_auth_key(
                        &daemon.state_dir,
                        auth_key,
                        invite_code.as_deref(),
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
        "invite_create" => {
            let coord_addr = daemon_coord_addr(&daemon)?;
            let ttl_secs = request
                .params
                .get("ttl_secs")
                .and_then(|v| v.as_i64())
                .unwrap_or(900);
            let max_uses = request
                .params
                .get("max_uses")
                .and_then(|v| v.as_i64())
                .unwrap_or(1);
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
            let owner_name = request
                .params
                .get("owner_name")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let node_ttl_days = request.params.get("node_ttl_days").and_then(|v| v.as_i64());
            let issued = admin_create_invite(
                &daemon.state_dir,
                &coord_addr,
                ttl_secs,
                max_uses,
                &tags,
                owner_name,
                node_ttl_days,
            )
            .await
            .map_err(|error| format!("{error:#}"))?;
            Ok(serde_json::json!({ "invite_code": issued.invite_code }))
        }
        "invite_list" => {
            let coord_addr = daemon_coord_addr(&daemon)?;
            let invites = admin_list_invites(&daemon.state_dir, &coord_addr)
                .await
                .map_err(|error| format!("{error:#}"))?;
            let items: Vec<serde_json::Value> = invites
                .into_iter()
                .map(|summary| {
                    serde_json::json!({
                        "invite_id": summary.invite_id,
                        "expires_at_unix": summary.expires_at_unix,
                        "max_uses": summary.max_uses,
                        "use_count": summary.use_count,
                        "tags": summary.tags,
                        "owner_name": summary.owner_name,
                        "revoked": summary.revoked,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "invites": items }))
        }
        "invite_revoke" => {
            let coord_addr = daemon_coord_addr(&daemon)?;
            let invite_id = request
                .params
                .get("invite_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "缺少 invite_id".to_string())?;
            admin_revoke_invite(&daemon.state_dir, &coord_addr, invite_id)
                .await
                .map_err(|error| format!("{error:#}"))?;
            Ok(serde_json::json!({ "revoked": invite_id }))
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

/// `status` IPC 方法的完整响应（diagnostics 复用同一形状，#84）。
async fn status_value(daemon: &Daemon) -> Result<Value, String> {
    let registration = daemon
        .registration
        .lock()
        .expect("registration poisoned")
        .clone();
    // 未注册：保持只返回 {"registered": false}（既有 IPC 契约，daemon 测试锁定）。
    let status = match registration {
        Session::Registered(info) => NodeStatus::Registered(info),
        Session::Expired(info) => NodeStatus::Expired(info),
        Session::None => {
            return serde_json::to_value(NodeStatus::Unregistered).map_err(|e| e.to_string());
        }
    };
    let mut value = serde_json::to_value(status).map_err(|e| e.to_string())?;
    value["peers"] = serde_json::to_value(peers_view(daemon)).map_err(|e| e.to_string())?;
    value["desired_state"] = serde_json::json!(
        daemon
            .desired_state
            .lock()
            .expect("desired state poisoned")
            .as_str()
    );
    value["dns_suffix"] = serde_json::json!(hz_core::dns::dns_suffix());
    value["revoked"] = serde_json::json!(*daemon.revoked.lock().expect("revoked poisoned"));
    // #25：最近一次运行中路由修复与引导 DNS 回退，供 hz status 汇报。
    let route_repair = LAST_ROUTE_REPAIR
        .lock()
        .expect("route repair poisoned")
        .clone();
    value["diagnostics"] = serde_json::json!({
        "route_repair": route_repair,
        "dns_fallback": hz_core::outer_dns::global().last_fallback(),
    });
    value["policy"] = serde_json::json!({
        "version": daemon.policy_gate.version(),
        "dropped": daemon.policy_gate.dropped(),
    });
    Ok(value)
}

/// `hz up` / `hz login` 连接的 Coordination Server：显式 --coord → 注册时记下的
/// 地址（已注册含已过期的 Node 重新登录不应换服务器）→ hzd 的 HZD_COORD_ADDR
/// → 内置默认地址。空串视同未提供。
fn up_coord_addr(requested: Option<&str>, registered: Option<&str>, env: Option<&str>) -> String {
    [requested, registered, env]
        .into_iter()
        .flatten()
        .find(|addr| !addr.is_empty())
        .unwrap_or(DEFAULT_COORD_ADDR)
        .to_string()
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
    // 注册即接入（#81）：Desired State 写 `up`。
    *daemon.desired_state.lock().expect("desired state poisoned") = DesiredState::Up;
    if let Err(error) = save_desired_state(&daemon.state_dir, DesiredState::Up) {
        tracing::warn!(%error, "persist desired state failed");
    }
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
                let error = "登录等待超时（10 分钟），请重新执行 hz login（已加入 HzNet）或 hz up"
                    .to_string();
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
    let boot_endpoint = Arc::new(StdMutex::new(None));
    publish_lan_endpoint(engine.local_addr().port(), &boot_endpoint);

    // 全部数据面子任务的句柄（#81）：监督任务持有，down 时逐个 abort。
    let mut tasks = Vec::new();
    if let Ok(relay_addr) = std::env::var("HZD_RELAY_ADDR") {
        if !relay_addr.is_empty() {
            tasks.push(spawn_relay_supervisor(
                &engine,
                keys,
                &info.node_id,
                &relay_addr,
                daemon.egress_epoch.clone(),
            ));
        }
    }

    tasks.extend(spawn_tun_bridge(
        &engine,
        info,
        &daemon.map_cache,
        &daemon.policy_gate,
        daemon.probes.clone(),
        daemon.egress_epoch.receiver(),
    ));
    tasks.push(spawn_map_task(
        daemon.clone(),
        engine.clone(),
        info.node_id.clone(),
        boot_endpoint.clone(),
        coord_addr.to_string(),
        daemon.policy_gate.clone(),
    ));
    // 段内 DNS 应答地址：注册响应携带（#20）；旧服务端回落规格 A2 固定值。
    let dns_v4 = info
        .dns_v4
        .as_deref()
        .and_then(|text| text.parse().ok())
        .unwrap_or(hz_core::dns::DNS_BIND_V4);
    if let Err(error) = dns::spawn(daemon.map_cache.clone(), dns_v4).await {
        tracing::warn!(%error, "dns responder unavailable");
    } else {
        // 已启动过（幂等）时 up 恢复也要重新挂辅助地址与 resolver 接入。
        dns::reactivate(dns_v4);
    }
    tasks.push(spawn_endpoint_collector(
        daemon.clone(),
        engine.clone(),
        coord_addr.to_string(),
    ));
    #[cfg(target_os = "macos")]
    let boot_for_watch = boot_endpoint.clone();
    tasks.push(spawn_net_recovery(
        daemon,
        engine.clone(),
        coord_addr,
        boot_endpoint,
    ));
    tasks.push(spawn_portmap(daemon.clone(), engine.clone()));
    tasks.push(spawn_path_task(
        daemon.map_cache.clone(),
        daemon.map_signal.clone(),
        daemon.own_endpoints.clone(),
        daemon.use_relay.clone(),
        daemon.punch.clone(),
        daemon.punch_last.clone(),
        daemon.punch_obs.clone(),
        engine.clone(),
        keys.clone(),
        &info.node_id,
    ));
    #[cfg(target_os = "macos")]
    tasks.push(spawn_egress_watch(
        daemon,
        engine.clone(),
        coord_addr,
        boot_for_watch,
    ));

    // 监督任务：down 的取消信号一到就 abort 全部子任务（SocketEngine、TUN
    // 随句柄 drop 关闭；portmap 的 Drop 守卫在 abort 引发的 future drop 中
    // 尽力删除映射），然后等待它们退出。
    let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
    let supervisor = tokio::spawn(async move {
        if cancel_rx.changed().await.is_ok() {
            for task in &tasks {
                task.abort();
            }
            for task in tasks {
                let _ = task.await;
            }
        }
    });
    *daemon.dataplane.lock().expect("dataplane poisoned") = Some(DataplaneHandle {
        cancel: cancel_tx,
        supervisor,
    });
    *daemon.engine.lock().expect("engine poisoned") = Some(engine);
    Ok(())
}

/// 停掉数据面（#81 `down`）：取消监督任务 → abort 全部子任务（Network Map
/// 流随之断开、上报停止、Relay/STUN/TUN 尽拆）→ 还原系统 DNS 接入 →
/// 移除引擎引用。幂等：未运行时是空操作。
async fn shutdown_dataplane(daemon: &Arc<Daemon>) {
    let handle = daemon.dataplane.lock().expect("dataplane poisoned").take();
    if let Some(handle) = handle {
        let _ = handle.cancel.send(true);
        // abort 全部子任务通常在毫秒级；给慢路径留 10 秒。
        let _ = tokio::time::timeout(Duration::from_secs(10), handle.supervisor).await;
    }
    daemon.engine.lock().expect("engine poisoned").take();
    dns::deactivate();
    daemon
        .own_endpoints
        .lock()
        .expect("own endpoints poisoned")
        .clear();
    tracing::info!("dataplane stopped (desired state down)");
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

/// 重算 LAN Endpoint 并记日志。没有可用地址时清空槽位，避免继续上报旧值。
fn publish_lan_endpoint(port: u16, slot: &StdMutex<Option<SocketAddr>>) {
    let endpoint = lan_endpoint(port);
    *slot.lock().expect("lan endpoint poisoned") = endpoint;
    match endpoint {
        Some(endpoint) => tracing::info!(%endpoint, "reporting lan endpoint"),
        None => tracing::info!("no usable lan endpoint on physical egress; not reporting one"),
    }
}

/// macOS 出口监视：物理出口变化后重算 LAN Endpoint 并重新上报。
/// 已有长连 socket 的重绑仍随跨平台监视合流（#16）。
#[cfg(target_os = "macos")]
fn spawn_egress_watch(
    daemon: &Arc<Daemon>,
    engine: Arc<SocketEngine>,
    coord_addr: &str,
    boot: Arc<StdMutex<Option<SocketAddr>>>,
) -> tokio::task::JoinHandle<()> {
    let daemon = daemon.clone();
    let coord_addr = coord_addr.to_string();
    tokio::spawn(async move {
        let mut events = hz_core::netwatch_mac::spawn_watcher();
        while let Some(event) = events.recv().await {
            tracing::info!(?event, "egress changed; recomputing lan endpoint");
            publish_lan_endpoint(engine.local_addr().port(), &boot);
            collect_and_report(&daemon, &engine, &coord_addr).await;
        }
    })
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
) -> tokio::task::JoinHandle<()> {
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
    })
}

/// STUN 服务器列表。`HZD_STUN_ADDR` 显式设置时按逗号拆开（可多个，供
/// netcheck 比较映射端口）；未设置时从 `HZD_RELAY_ADDR` 的主机推导
/// UDP 3478 与 3479 两个目标（FR-8：STUN 与 Relay 同主机；#76：Relay 缺省
/// 双端口，两个目标比较映射端口得到 nat=easy/hard）。周期收集只用第一个。
fn stun_server_targets() -> Vec<String> {
    stun_targets_from(
        std::env::var("HZD_STUN_ADDR").ok(),
        std::env::var("HZD_RELAY_ADDR").ok(),
    )
}

fn stun_server_target() -> Option<String> {
    stun_server_targets().into_iter().next()
}

fn stun_targets_from(explicit: Option<String>, relay: Option<String>) -> Vec<String> {
    if let Some(raw) = explicit {
        return raw
            .split(',')
            .map(str::trim)
            .filter(|target| !target.is_empty())
            .map(str::to_string)
            .collect();
    }
    relay
        .and_then(|relay| relay_host_of(&relay))
        .map(|host| vec![format!("{host}:3478"), format!("{host}:3479")])
        .unwrap_or_default()
}

/// 地址串的主机部分（去 scheme、去端口）。
fn relay_host_of(relay: &str) -> Option<String> {
    let host_port = relay
        .rsplit_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(relay);
    let host = host_port
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(host_port);
    (!host.is_empty()).then(|| host.to_string())
}

/// 解析一个 STUN 目标的全部地址（A 与 AAAA）。经外层解析器（系统 DNS
/// 返回假地址时改问引导 DNS，#23），在阻塞线程池里做。
async fn resolve_stun_all(target: &str) -> Vec<SocketAddr> {
    let owned = target.to_string();
    match tokio::task::spawn_blocking(move || hz_core::outer_dns::resolve_host_port(&owned)).await {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(error)) => {
            tracing::warn!(%target, %error, "STUN 服务器地址解析失败");
            Vec::new()
        }
        Err(error) => {
            tracing::warn!(%target, %error, "STUN 地址解析任务异常");
            Vec::new()
        }
    }
}

/// 每轮解析 STUN 地址：取 [`resolve_stun_all`] 的第一个。
async fn resolve_stun(target: &str) -> Option<SocketAddr> {
    resolve_stun_all(target).await.into_iter().next()
}

async fn all_stun_addrs() -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for target in stun_server_targets() {
        for addr in resolve_stun_all(&target).await {
            if !out.contains(&addr) {
                out.push(addr);
            }
        }
    }
    out
}

fn offline_udp() -> UdpProbe {
    UdpProbe {
        ok: false,
        stage: Some("query".to_string()),
        error: Some("数据面未启动".to_string()),
        mapped: None,
    }
}

struct FamilyProbe {
    head: UdpProbe,
    mapped: Vec<SocketAddr>,
    rtt_ms: Option<f64>,
}

async fn probe_family(engine: &SocketEngine, targets: &[SocketAddr]) -> FamilyProbe {
    if targets.is_empty() {
        return FamilyProbe {
            head: UdpProbe {
                ok: false,
                stage: Some("query".to_string()),
                error: Some("无该族 STUN 目标".to_string()),
                mapped: None,
            },
            mapped: Vec::new(),
            rtt_ms: None,
        };
    }
    let mut head = None;
    let mut mapped = Vec::new();
    let mut rtt_ms = None;
    for server in targets {
        let started = std::time::Instant::now();
        match engine.stun_query(*server).await {
            Ok(addr) => {
                if head.is_none() {
                    head = Some(UdpProbe {
                        ok: true,
                        stage: None,
                        error: None,
                        mapped: Some(addr.to_string()),
                    });
                    rtt_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
                }
                mapped.push(addr);
            }
            Err(error) => {
                if head.is_none() {
                    let (stage, token) = netcheck::classify_udp_error(&error);
                    let send_failed = stage == "send";
                    head = Some(UdpProbe {
                        ok: false,
                        stage: Some(stage.to_string()),
                        error: Some(token),
                        mapped: None,
                    });
                    // 同一 socket 上这一族的发送都会以同样的 errno 失败。
                    if send_failed {
                        break;
                    }
                }
            }
        }
    }
    FamilyProbe {
        head: head.expect("targets non-empty"),
        mapped,
        rtt_ms,
    }
}

async fn probe_stun(
    engine: &SocketEngine,
    targets: &[SocketAddr],
) -> (UdpReport, StunReport, Option<f64>) {
    let v4: Vec<SocketAddr> = targets
        .iter()
        .copied()
        .filter(|addr| addr.is_ipv4())
        .collect();
    let v6: Vec<SocketAddr> = targets
        .iter()
        .copied()
        .filter(|addr| addr.is_ipv6())
        .collect();
    let ipv4 = probe_family(engine, &v4).await;
    let ipv6 = probe_family(engine, &v6).await;
    let ports: Vec<u16> = ipv4.mapped.iter().map(|addr| addr.port()).collect();
    let mut mapped = Vec::new();
    mapped.extend(ipv4.mapped.iter().map(|addr| addr.to_string()));
    mapped.extend(ipv6.mapped.iter().map(|addr| addr.to_string()));
    let stun = StunReport {
        targets: targets.len(),
        mapped,
        nat: netcheck::nat_verdict(v4.len(), &ports).to_string(),
    };
    (
        UdpReport {
            ipv4: ipv4.head,
            ipv6: ipv6.head,
        },
        stun,
        ipv4.rtt_ms.or(ipv6.rtt_ms),
    )
}

fn noted_endpoints(found: &[DiscoveredEndpoint]) -> Vec<EndpointNote> {
    found
        .iter()
        .map(|endpoint| {
            let on_virtual = hz_core::netif::interface_with_addr(endpoint.addr.ip())
                .is_some_and(|name| hz_core::netif::is_virtual_iface(&name));
            EndpointNote {
                addr: endpoint.addr.to_string(),
                kind: endpoint.kind.as_str().to_string(),
                suspicious: netcheck::suspicions(endpoint.addr.ip(), on_virtual)
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            }
        })
        .collect()
}

fn peer_notes(daemon: &Daemon) -> Vec<hz_core::netcheck::PeerNote> {
    if daemon.is_expired() {
        return Vec::new();
    }
    let own = daemon.registration_info().map(|info| info.node_id);
    let engine = daemon.engine.lock().expect("engine poisoned").clone();
    let reports: HashMap<String, PeerReport> = engine
        .as_ref()
        .map(|engine| {
            engine
                .peer_reports()
                .into_iter()
                .map(|report| (report.node_id.clone(), report))
                .collect()
        })
        .unwrap_or_default();
    let punch = daemon
        .punch_last
        .lock()
        .expect("punch last poisoned")
        .clone();
    // Relay 原因（#72）：netcheck 的对端行与健康报告同一判定函数。
    let reasons = match &engine {
        Some(engine) => relay_reason_map(
            daemon, engine,
            // 原因判定用的 UDP 结论在 collect_netcheck 里现场探测，这里拿不到；
            // 传 true 让 local_udp_broken 只由周期上报那条路径报出。
            true,
        ),
        None => HashMap::new(),
    };
    daemon
        .map_cache
        .snapshot()
        .into_iter()
        .filter(|node| own.as_deref() != Some(node.node_id.as_str()))
        .map(|node| {
            let report = reports.get(&node.node_id);
            let path = report.map(|report| if report.use_relay { "relay" } else { "direct" });
            hz_core::netcheck::PeerNote {
                relay_reason: match path {
                    Some("relay") => reasons.get(&node.node_id).copied().map(str::to_string),
                    _ => None,
                },
                path: path.map(str::to_string),
                punch: punch.get(&node.node_id).cloned(),
                name: node.name,
                node_id: node.node_id,
            }
        })
        .collect()
}

async fn collect_netcheck(daemon: &Daemon) -> NetcheckReport {
    let egress = hz_core::netif::route_picture();
    let ipv6_usable = hz_core::endpoint::has_usable_ipv6();
    let endpoints = {
        let found = daemon
            .own_endpoints
            .lock()
            .expect("own endpoints poisoned")
            .clone();
        noted_endpoints(&found)
    };
    let peers = peer_notes(daemon);
    let engine = daemon.engine.lock().expect("engine poisoned").clone();
    let targets = all_stun_addrs().await;
    let (udp, stun, relay_rtt_ms) = match &engine {
        Some(engine) => probe_stun(engine, &targets).await,
        None => {
            let v4 = targets.iter().filter(|addr| addr.is_ipv4()).count();
            (
                UdpReport {
                    ipv4: offline_udp(),
                    ipv6: offline_udp(),
                },
                StunReport {
                    targets: targets.len(),
                    mapped: Vec::new(),
                    nat: netcheck::nat_verdict(v4, &[]).to_string(),
                },
                None,
            )
        }
    };
    NetcheckReport {
        egress,
        udp,
        stun,
        endpoints,
        ipv6_usable,
        relay_rtt_ms,
        portmap: daemon
            .portmap_status
            .lock()
            .expect("portmap status poisoned")
            .clone(),
        peers,
    }
}

/// 端口映射开关（#77）：HZD_PORTMAP=0 关闭——不发起任何映射请求，
/// 适合不希望 hzd 改路由器配置的网络。
fn portmap_enabled() -> bool {
    std::env::var("HZD_PORTMAP").ok().as_deref() != Some("0")
}

/// 端口映射的网关端点：`HZD_PORTMAP_GATEWAY`（`ip` 或 `ip:port`，缺省端口
/// 5351）显式指定，否则默认网关 + 5351。显式指定主要供测试注入桩网关，
/// 也可用于网关不在默认路由上的网络。
fn portmap_gateway_endpoint() -> Option<std::net::SocketAddr> {
    if let Ok(raw) = std::env::var("HZD_PORTMAP_GATEWAY") {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        if let Ok(endpoint) = raw.parse() {
            return Some(endpoint);
        }
        let ip: std::net::IpAddr = raw.parse().ok()?;
        return Some(std::net::SocketAddr::new(
            ip,
            hz_core::portmap::GATEWAY_PORT,
        ));
    }
    hz_core::netif::default_gateway_v4().map(|gateway| {
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(gateway),
            hz_core::portmap::GATEWAY_PORT,
        )
    })
}

/// 端口映射监督任务（#77）：申请 → 发布 PortMap 候选 → 租期过半续租；
/// 物理出口变化时立即重新申请；任务结束（hzd 退出）时尽力删除映射。
fn spawn_portmap(daemon: Arc<Daemon>, engine: Arc<SocketEngine>) -> tokio::task::JoinHandle<()> {
    if !portmap_enabled() {
        tracing::debug!("portmap disabled by HZD_PORTMAP=0");
        return tokio::spawn(async {});
    }
    let egress = daemon.egress_epoch.receiver();
    tokio::spawn(async move {
        let mut egress = egress;
        let mut egress_open = true;
        // Drop 时同步发出 lifetime=0 的删除报文（PCP/NAT-PMP）。
        struct PortMapDropGuard(Option<hz_core::portmap::PortMapLease>);
        impl Drop for PortMapDropGuard {
            fn drop(&mut self) {
                let Some(lease) = &self.0 else { return };
                let Some((gateway, datagram)) = hz_core::portmap::delete_datagram(lease) else {
                    return;
                };
                let socket = std::net::UdpSocket::bind("0.0.0.0:0");
                if let Ok(socket) = socket {
                    let _ = socket.send_to(&datagram, gateway);
                    tracing::info!(
                        protocol = lease.protocol.as_str(),
                        "port mapping deleted on shutdown"
                    );
                }
            }
        }
        let mut guard = PortMapDropGuard(None);
        // 上一份租约：续租时传给申请（PCP 复用 nonce、沿用旧外端口，候选不漂移）。
        let mut lease: Option<hz_core::portmap::PortMapLease> = None;
        loop {
            let wg_port = engine.local_addr().port();
            let mut wait = Duration::from_secs(60);
            match portmap_gateway_endpoint() {
                Some(endpoint) if endpoint.is_ipv4() => {
                    match hz_core::portmap::request_mapping_at(
                        endpoint,
                        wg_port,
                        lease.as_ref(),
                        true,
                    )
                    .await
                    {
                        Ok(Some(hz_core::portmap::MappingOutcome::Mapped(established))) => {
                            tracing::info!(
                                protocol = established.protocol.as_str(),
                                external = %established.external,
                                lifetime_secs = established.lifetime_secs,
                                "port mapping established"
                            );
                            *daemon
                                .portmap_status
                                .lock()
                                .expect("portmap status poisoned") =
                                hz_core::netcheck::PortMapNote {
                                    protocol: Some(established.protocol.as_str().to_string()),
                                    external: Some(established.external.to_string()),
                                    multi_nat: false,
                                };
                            daemon
                                .portmap_endpoint
                                .lock()
                                .expect("portmap endpoint poisoned")
                                .replace(DiscoveredEndpoint {
                                    addr: established.external,
                                    kind: hz_core::endpoint::EndpointKind::PortMap,
                                });
                            merge_portmap_into(&daemon);
                            // 新候选尽快报给 coord（等不及 30 秒的下一轮收集）。
                            let coord_addr = {
                                daemon
                                    .coord_addr
                                    .lock()
                                    .expect("coord addr poisoned")
                                    .clone()
                                    .filter(|addr| !addr.is_empty())
                            };
                            if let Some(coord_addr) = coord_addr {
                                collect_and_report(&daemon, &engine, &coord_addr).await;
                            }
                            // 租期过半续租（下限 30 秒，防短租期自旋）。
                            wait =
                                Duration::from_secs((established.lifetime_secs as u64 / 2).max(30));
                            guard.0 = Some(established.clone());
                            lease = Some(established);
                        }
                        Ok(Some(hz_core::portmap::MappingOutcome::MultiNat {
                            protocol,
                            external,
                        })) => {
                            tracing::warn!(
                                protocol = protocol.as_str(),
                                %external,
                                "port mapping behind another NAT (multi-NAT); not reporting a candidate, consider bridging the modem"
                            );
                            *daemon
                                .portmap_status
                                .lock()
                                .expect("portmap status poisoned") =
                                hz_core::netcheck::PortMapNote {
                                    protocol: Some(protocol.as_str().to_string()),
                                    external: Some(external.to_string()),
                                    multi_nat: true,
                                };
                            daemon
                                .portmap_endpoint
                                .lock()
                                .expect("portmap endpoint poisoned")
                                .take();
                            merge_portmap_into(&daemon);
                        }
                        Ok(None) => {
                            *daemon
                                .portmap_status
                                .lock()
                                .expect("portmap status poisoned") =
                                hz_core::netcheck::PortMapNote::default();
                            daemon
                                .portmap_endpoint
                                .lock()
                                .expect("portmap endpoint poisoned")
                                .take();
                            merge_portmap_into(&daemon);
                        }
                        Err(error) => {
                            // 传输层错误（socket 建立失败等）视为暂时性：保留上次的
                            // 状态与候选不清空，与 Ok(None)（确定无网关应答）不同。
                            tracing::debug!(%error, "portmap request failed");
                        }
                    }
                }
                None => {
                    tracing::debug!("no default gateway; port mapping not attempted");
                }
                // IPv6 网关：端口映射协议只走 IPv4，本轮跳过。
                Some(_) => {
                    tracing::debug!("portmap gateway must be IPv4");
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                changed = egress.changed(), if egress_open => {
                    egress_open = changed.is_ok();
                    tracing::info!("egress changed, re-requesting port mapping");
                }
            }
        }
    })
}

/// 把端口映射候选并入 own_endpoints（替换既有 PortMap 项；无映射时移除）。
/// 周期收集会整体覆盖槽位，收集结束后与映射任务更新后都要调一次。
fn merge_portmap_into(daemon: &Arc<Daemon>) {
    let portmap = daemon
        .portmap_endpoint
        .lock()
        .expect("portmap endpoint poisoned")
        .clone();
    let mut own = daemon.own_endpoints.lock().expect("own endpoints poisoned");
    own.retain(|found| found.kind != hz_core::endpoint::EndpointKind::PortMap);
    if let Some(portmap) = portmap {
        own.push(portmap);
    }
}

/// Endpoint 收集与上报（FR-8）：周期性收集 Lan/STUN/V6，ReportEndpoints 落库，
/// 结果同时存进共享槽供打洞信令取本机候选；打洞累计计数随上报携带（FR-12）；
/// Health Report（#72 / OB-2）同帧上报，netcheck 六项与 Relay 原因在本帧
/// 现场判定。收集动作本身抽成 [`collect_and_report`]，网络变化恢复序列即时复用。
fn spawn_endpoint_collector(
    daemon: Arc<Daemon>,
    engine: Arc<SocketEngine>,
    coord_addr: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(ENDPOINT_COLLECT_EVERY);
        loop {
            ticker.tick().await;
            collect_and_report(&daemon, &engine, &coord_addr).await;
        }
    })
}

/// 一轮 STUN 探测的结论：Endpoint 候选 + Health Report 的 netcheck 输入。
/// 逐目标查询（最多前两个：周期收集用第一个出候选，两个比较映射端口得
/// NAT 形态，#76）；同族失败即停（EINVAL 之类每目标都会同样失败）。
#[derive(Debug, Default)]
struct StunRound {
    /// 第一个目标的映射（Endpoint 候选来源，None = 不可达）。
    first_mapped: Option<SocketAddr>,
    udp4_ok: bool,
    udp6_ok: bool,
    /// 每个目标的 IPv4 映射端口（NAT 比较用）。
    mapped_ports: Vec<u16>,
}

async fn stun_round(engine: &Arc<SocketEngine>, targets: &[String]) -> StunRound {
    let mut round = StunRound::default();
    let mut send_broken_v4 = false;
    let mut send_broken_v6 = false;
    for (index, target) in targets.iter().take(2).enumerate() {
        let Some(server) = resolve_stun(target).await else {
            continue;
        };
        match engine.stun_query(server).await {
            Ok(mapped) => {
                if mapped.is_ipv4() {
                    round.udp4_ok = true;
                    round.mapped_ports.push(mapped.port());
                } else {
                    round.udp6_ok = true;
                }
                if index == 0 {
                    tracing::info!(%mapped, "stun mapped endpoint discovered");
                    round.first_mapped = Some(mapped);
                }
            }
            Err(error) => {
                let (stage, token) = netcheck::classify_udp_error(&error);
                tracing::warn!(%server, stage, error = %token, "stun query failed");
                // 发送失败（如 macOS 双栈 EINVAL）同族每个目标都会失败，不重试。
                if stage == "send" {
                    if server.is_ipv4() {
                        send_broken_v4 = true;
                    } else {
                        send_broken_v6 = true;
                    }
                }
            }
        }
        if send_broken_v4 && send_broken_v6 {
            break;
        }
    }
    round
}

/// 每个走 Relay 的对端的原因（规格 §4，纯函数 [`relay_reason`] 的装配）。
fn relay_reason_map(
    daemon: &Daemon,
    engine: &SocketEngine,
    local_udp_ok: bool,
) -> HashMap<String, &'static str> {
    let own_node_id = daemon
        .registration_info()
        .map(|info| info.node_id)
        .unwrap_or_default();
    let peers = peer_endpoint_view(&daemon.map_cache, &own_node_id);
    let direct_rx = engine.direct_rx_ages();
    let obs = daemon.punch_obs.lock().expect("punch obs poisoned").clone();
    engine
        .peer_reports()
        .into_iter()
        .filter(|report| report.use_relay)
        .filter_map(|report| {
            let peer = peers
                .iter()
                .find(|peer| peer.endpoints.node_id == report.node_id)?;
            let obs = obs.get(&report.node_id).copied().unwrap_or_default();
            let rx_fresh = direct_rx
                .get(&report.node_id)
                .and_then(|age| *age)
                .is_some_and(|age| age <= hz_core::path::DIRECT_RX_FRESH);
            let _ = obs; // offer_at 仅日志/调试用，原因判定只看 ack（§4）
            let reason = relay_reason(&hz_core::health::RelayReasonInput {
                local_udp_ok,
                peer_has_candidates: !(peer.endpoints.v6.is_empty()
                    && peer.endpoints.stun.is_empty()
                    && peer.endpoints.lan.is_empty()),
                signaling_exchanged: obs.ack_at.is_some(),
                direct_rx_fresh: rx_fresh,
            });
            Some((report.node_id, reason))
        })
        .collect()
}

/// 组装一份 Health Report（规格 §3）。netcheck 六项来自本轮 STUN 探测与
/// 状态采集，`direct_peers` / `relayed_peers` 来自数据面现状 + 原因判定。
fn build_health_snapshot(
    daemon: &Daemon,
    engine: &SocketEngine,
    stun: &StunRound,
) -> HealthSnapshot {
    let reasons = relay_reason_map(daemon, engine, stun.udp4_ok || stun.udp6_ok);
    let mut direct_peers = 0u32;
    let mut relayed_peers = Vec::new();
    for report in engine.peer_reports() {
        if report.use_relay {
            if let Some(reason) = reasons.get(&report.node_id) {
                relayed_peers.push(RelayedPeerNote {
                    node_id: report.node_id.clone(),
                    reason,
                });
            }
        } else {
            direct_peers += 1;
        }
    }
    let found = daemon
        .own_endpoints
        .lock()
        .expect("own endpoints poisoned")
        .clone();
    let suspicious_endpoint = noted_endpoints(&found).iter().any(|note| {
        note.suspicious
            .iter()
            .any(|flag| flag == "198.18.0.0/15" || flag == "loopback")
    });
    let route = hz_core::netif::route_picture();
    HealthSnapshot {
        udp4_ok: stun.udp4_ok,
        udp6_ok: stun.udp6_ok,
        has_stun_mapping: stun.first_mapped.is_some() || !stun.mapped_ports.is_empty(),
        nat: nat_kind(&stun.mapped_ports),
        default_route_virtual: route.virtual_holds_default,
        suspicious_endpoint,
        direct_peers,
        relayed_peers,
    }
}

/// 收集一轮本机 Endpoint 并上报（周期收集与网络变化恢复共用）：
/// STUN 查询走引擎共享 socket（重绑后自动落在新出口上），结果连同
/// Lan/V6 候选写入共享槽并 ReportEndpoints 给 Coordination Server；
/// Health Report 同帧携带（#72）。
async fn collect_and_report(daemon: &Arc<Daemon>, engine: &Arc<SocketEngine>, coord_addr: &str) {
    let targets = stun_server_targets();
    let round = stun_round(engine, &targets).await;
    let mut found = endpoint::collect(engine.local_addr().port(), round.first_mapped);
    // 端口映射候选（#77）并入本轮结果一起上报与共享（替换旧 PortMap 项）。
    let portmap = daemon
        .portmap_endpoint
        .lock()
        .expect("portmap endpoint poisoned")
        .clone();
    found.retain(|endpoint| endpoint.kind != hz_core::endpoint::EndpointKind::PortMap);
    if let Some(portmap) = portmap {
        found.push(portmap);
    }
    tracing::info!(endpoints = ?found, "collected endpoints");
    *daemon.own_endpoints.lock().expect("own endpoints poisoned") = found.clone();
    let counters = *daemon.punch.lock().expect("punch counters poisoned");
    let snapshot = build_health_snapshot(daemon, engine, &round);
    if let Err(error) = report_endpoints(
        &daemon.state_dir,
        &found,
        coord_addr,
        Some(counters),
        Some(&snapshot),
    )
    .await
    {
        tracing::warn!(%error, "endpoint report to coord failed");
    }
}

/// 网络变化恢复序列（FR-8 本机网络变化后自动恢复）。netwatch 的去抖事件
/// 到来时重算快照：确有变化（或休眠唤醒）才执行——重绑 UDP socket 到新
/// 物理出口 → 作废直连记账 → 即时 STUN + ReportEndpoints（对端拿到新公网
/// 映射）→ 递增出口代数（Map 订阅与 Relay 长连接立刻重拨）→ 唤醒路径任务
/// 重启打洞。全部动作幂等，事件风暴下重复执行也收敛到同一终态。
/// 非 Linux 上 netwatch 无事件（#16），本任务随即退出。
fn spawn_net_recovery(
    daemon: &Arc<Daemon>,
    engine: Arc<SocketEngine>,
    coord_addr: &str,
    boot: Arc<StdMutex<Option<SocketAddr>>>,
) -> tokio::task::JoinHandle<()> {
    let daemon = daemon.clone();
    let map_signal = daemon.map_signal.clone();
    let egress_epoch = daemon.egress_epoch.clone();
    let coord_addr = coord_addr.to_string();
    tokio::spawn(async move {
        let mut events = netwatch::spawn();
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
            publish_lan_endpoint(engine.local_addr().port(), &boot);
            // 换网瞬间路由可能尚未收敛：STUN 限次重试，给出口几秒钟。
            let has_stun_target = stun_server_target().is_some();
            for round in 0..3 {
                collect_and_report(&daemon, &engine, &coord_addr).await;
                let stun_reached = !has_stun_target
                    || daemon
                        .own_endpoints
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
    })
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
    punch_last: Arc<StdMutex<HashMap<String, String>>>,
    punch_obs: Arc<StdMutex<HashMap<String, PunchObs>>>,
    engine: Arc<SocketEngine>,
    keys: Arc<KeyStore>,
    own_node_id: &str,
) -> tokio::task::JoinHandle<()> {
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
                                &cache, &own_node_id, &engine, &keys, &mut manager, &punch_obs, &frame,
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
                    &punch_last,
                    &punch_obs,
                    &keys,
                    &peers,
                    event,
                )
                .await;
            }
        }
    })
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
                    hz_core::endpoint::EndpointKind::Stun
                    | hz_core::endpoint::EndpointKind::PortMap => endpoints.stun.push(addr),
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

#[allow(clippy::too_many_arguments)]
async fn apply_path_event(
    engine: &Arc<SocketEngine>,
    own_slot: &Arc<StdMutex<Vec<DiscoveredEndpoint>>>,
    use_relay_slot: &Arc<StdMutex<HashMap<String, bool>>>,
    punch_slot: &Arc<StdMutex<PunchCounters>>,
    punch_last: &Arc<StdMutex<HashMap<String, String>>>,
    punch_obs: &Arc<StdMutex<HashMap<String, PunchObs>>>,
    keys: &Arc<KeyStore>,
    peers: &[PeerView],
    event: PathEvent,
) {
    let forced = force_relay();
    match event {
        PathEvent::SetUseRelay { node_id, use_relay } => {
            note_punch(
                punch_last,
                &node_id,
                if use_relay { "fallback" } else { "success" },
            );
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
                note_punch(punch_last, &node_id, "skipped");
                return;
            }
            // 一轮打洞（Offer + 握手并发，FR-12 成功率分母）。
            punch_slot.lock().expect("punch counters poisoned").attempts += 1;
            punch_obs
                .lock()
                .expect("punch obs poisoned")
                .entry(node_id.clone())
                .or_default()
                .offer_at = Some(std::time::Instant::now());
            let Some(relay) = engine.relay_client() else {
                tracing::debug!(%node_id, "punch offer skipped: no relay transport");
                note_punch(punch_last, &node_id, "skipped");
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
            note_punch(punch_last, &node_id, "attempted");
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

fn note_punch(slot: &StdMutex<HashMap<String, String>>, node_id: &str, result: &str) {
    slot.lock()
        .expect("punch last poisoned")
        .insert(node_id.to_string(), result.to_string());
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
    punch_obs: &Arc<StdMutex<HashMap<String, PunchObs>>>,
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
                // 对端已发起打洞：记入观察（Relay 原因判定输入）。
                punch_obs
                    .lock()
                    .expect("punch obs poisoned")
                    .entry(peer.endpoints.node_id.clone())
                    .or_default()
                    .offer_at = Some(std::time::Instant::now());
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
                // 信令已往来（规格 §4 handshake_timeout 的前置）。
                punch_obs
                    .lock()
                    .expect("punch obs poisoned")
                    .entry(peer.endpoints.node_id.clone())
                    .or_default()
                    .ack_at = Some(std::time::Instant::now());
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
    egress: tokio::sync::watch::Receiver<u64>,
) -> Vec<tokio::task::JoinHandle<()>> {
    // down（#81）靠监督任务 abort 这些句柄拆数据面：全部子任务都要收进 Vec。
    let mut tasks = Vec::new();
    let (to_tunnel_tx, to_tunnel_rx) = mpsc::channel::<Vec<u8>>(256);
    tasks.push(tokio::spawn({
        let engine = engine.clone();
        async move {
            if let Err(error) = engine.run(to_tunnel_tx).await {
                tracing::error!(%error, "wireguard engine loop exited");
            }
        }
    }));
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
                tasks.push(spawn_tunnel_drain(
                    engine.clone(),
                    probes,
                    own_v4,
                    to_tunnel_rx,
                ));
                return tasks;
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
                tasks.push(spawn_route_guard(Arc::new(tun), egress.clone()));
                tasks.push(tokio::spawn({
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
                }));
                let engine = engine.clone();
                let cache = cache.clone();
                let gate = gate.clone();
                tasks.push(tokio::spawn(async move {
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
                }));
            }
            Err(error) => {
                tracing::warn!(%error, "tun setup failed, running without data plane forwarding");
                tasks.push(spawn_tunnel_drain(
                    engine.clone(),
                    probes,
                    own_v4,
                    to_tunnel_rx,
                ));
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (cache, gate, egress);
        tasks.push(spawn_tunnel_drain(
            engine.clone(),
            probes,
            own_v4,
            to_tunnel_rx,
        ));
    }
    tasks
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
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(packet) = rx.recv().await {
            if let Some(v4) = own_v4 {
                if ping::intercept(&engine, &probes, v4, &packet).await {
                    continue;
                }
            }
        }
    })
}

/// 从 Map 消失后向服务端问一次，区分吊销与到期（removed 差量不携带原因，
/// 两种结局共享 Expired 会话态）。吊销态决定 `hz status` 文案：已吊销
/// 不能靠重新登录恢复，重新加入只能以全新身份注册。
async fn note_revocation(
    daemon: &Arc<Daemon>,
    state_dir: &std::path::Path,
    endpoints: Vec<String>,
    coord_addr: &str,
) {
    match open_network_map_stream(state_dir, endpoints, coord_addr).await {
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
/// 取共享槽里的最新收集结果（出口变化后重拨不会把旧地址写回去），
/// 槽为空才退回最近一次算出的 LAN Endpoint（没有可用地址则不上报）。
/// Map 有实际变化时唤醒路径任务（打洞轮次紧跟对端 Endpoint 更新）。
/// 到期反应（FR-3）：自己出现在 removed 差量、或订阅被服务端以「已过期」
/// 拒绝时，转入 Expired 并拆掉对端，随后驻留轮询——不退避重连浪费连接，
/// 重新登录完成后状态翻回 Registered，本任务自动恢复订阅。
/// 物理出口变化（egress_epoch）不等 TCP 死亡立刻强制重拨（FR-8 恢复）。
fn spawn_map_task(
    daemon: Arc<Daemon>,
    engine: Arc<SocketEngine>,
    own_node_id: String,
    boot_endpoint: Arc<StdMutex<Option<SocketAddr>>>,
    coord_addr: String,
    policy_gate: Arc<InboundGate>,
) -> tokio::task::JoinHandle<()> {
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
                                let probe_endpoints = endpoint_strings(&own_slot, &boot_endpoint);
                                note_revocation(&daemon, &state_dir, probe_endpoints, &coord_addr)
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
    })
}

/// Map 订阅随流携带的 Endpoint 字符串：共享槽的最新收集结果；空槽（收集
/// 尚未跑过）退回最近一次 LAN Endpoint。没有可用地址时给空列表——服务端
/// 接受空上报，不能塞一个空字符串或已经失效的旧地址。
fn endpoint_strings(
    own_slot: &Arc<StdMutex<Vec<DiscoveredEndpoint>>>,
    boot_endpoint: &Arc<StdMutex<Option<SocketAddr>>>,
) -> Vec<String> {
    let collected = own_slot.lock().expect("own endpoints poisoned").clone();
    if !collected.is_empty() {
        return collected
            .into_iter()
            .map(|found| found.addr.to_string())
            .collect();
    }
    boot_endpoint
        .lock()
        .expect("lan endpoint poisoned")
        .map(|addr| vec![addr.to_string()])
        .unwrap_or_default()
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

#[cfg(test)]
mod desired_state_tests {
    use super::*;

    #[test]
    fn missing_or_corrupt_file_defaults_to_up() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_desired_state(dir.path()), DesiredState::Up);
        std::fs::write(dir.path().join(DESIRED_STATE_FILE), "not json").unwrap();
        assert_eq!(load_desired_state(dir.path()), DesiredState::Up);
        std::fs::write(dir.path().join(DESIRED_STATE_FILE), r#"{"state":"down"}"#).unwrap();
        assert_eq!(load_desired_state(dir.path()), DesiredState::Down);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        save_desired_state(dir.path(), DesiredState::Down).unwrap();
        assert_eq!(load_desired_state(dir.path()), DesiredState::Down);
        save_desired_state(dir.path(), DesiredState::Up).unwrap();
        assert_eq!(load_desired_state(dir.path()), DesiredState::Up);
        // 权限 0600，与 registration.json 一致。
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join(DESIRED_STATE_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[cfg(test)]
mod up_coord_addr_tests {
    use super::*;

    #[test]
    fn explicit_coord_wins() {
        assert_eq!(
            up_coord_addr(Some("https://a"), Some("https://reg"), Some("https://env")),
            "https://a"
        );
    }

    #[test]
    fn registered_addr_beats_env() {
        assert_eq!(
            up_coord_addr(None, Some("https://reg"), Some("https://env")),
            "https://reg"
        );
    }

    #[test]
    fn env_then_default_when_unregistered() {
        assert_eq!(
            up_coord_addr(None, None, Some("https://env")),
            "https://env"
        );
        assert_eq!(up_coord_addr(None, Some(""), Some("")), DEFAULT_COORD_ADDR);
        assert_eq!(up_coord_addr(None, None, None), DEFAULT_COORD_ADDR);
    }
}

#[cfg(test)]
mod endpoint_strings_tests {
    use super::*;
    use hz_core::endpoint::EndpointKind;

    fn slot(addrs: &[&str]) -> Arc<StdMutex<Vec<DiscoveredEndpoint>>> {
        Arc::new(StdMutex::new(
            addrs
                .iter()
                .map(|text| DiscoveredEndpoint {
                    addr: text.parse().unwrap(),
                    kind: EndpointKind::Lan,
                })
                .collect(),
        ))
    }

    #[test]
    fn missing_lan_endpoint_is_omitted() {
        let boot = Arc::new(StdMutex::new(None));
        assert!(endpoint_strings(&slot(&[]), &boot).is_empty());
    }

    #[test]
    fn boot_lan_endpoint_tracks_egress_and_yields_to_collection() {
        let boot = Arc::new(StdMutex::new(Some("192.168.31.63:51820".parse().unwrap())));
        assert_eq!(
            endpoint_strings(&slot(&[]), &boot),
            vec!["192.168.31.63:51820".to_string()]
        );
        *boot.lock().expect("lan endpoint poisoned") = Some("10.0.0.8:51820".parse().unwrap());
        assert_eq!(
            endpoint_strings(&slot(&[]), &boot),
            vec!["10.0.0.8:51820".to_string()],
            "出口变化后重算的地址要出现在下一次上报里"
        );
        *boot.lock().expect("lan endpoint poisoned") = None;
        assert!(
            endpoint_strings(&slot(&[]), &boot).is_empty(),
            "重算后没有可用地址时不再上报旧值"
        );
        assert_eq!(
            endpoint_strings(&slot(&["10.1.1.1:51820"]), &boot),
            vec!["10.1.1.1:51820".to_string()]
        );
    }
}

#[cfg(test)]
mod netcheck_probe_tests {
    use std::sync::Arc;

    use hz_core::keys::NodeStaticSecret;
    use hz_core::stun;
    use hz_core::wire::SocketEngine;
    use rand_core::OsRng;

    use super::probe_stun;

    /// hzd 侧查询：共享 socket 上的 STUN 探测把 IPv4 成功与映射地址写进报告，
    /// 两个目标端口一致时 NAT 判为端点无关，没有 IPv6 目标时不猜测。
    #[tokio::test]
    async fn two_loopback_stun_targets_report_ipv4_udp_and_same_mapped_port() {
        let engine = Arc::new(
            SocketEngine::bind_with(NodeStaticSecret::random_from_rng(OsRng), 0, false)
                .await
                .unwrap(),
        );
        let (tunnel_tx, _tunnel_rx) = tokio::sync::mpsc::channel(8);
        let runner = engine.clone();
        let pump = tokio::spawn(async move {
            let _ = runner.run(tunnel_tx).await;
        });

        let mut tasks = Vec::new();
        let mut targets = Vec::new();
        for _ in 0..2 {
            let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
            targets.push(sock.local_addr().unwrap());
            tasks.push(tokio::spawn(stun::serve(sock)));
        }

        let (udp, stun_report, rtt) = probe_stun(&engine, &targets).await;
        pump.abort();
        for task in tasks {
            task.abort();
        }

        assert!(udp.ipv4.ok, "IPv4 STUN 应成功：{:?}", udp.ipv4);
        let mapped: std::net::SocketAddr = udp.ipv4.mapped.as_deref().unwrap().parse().unwrap();
        assert_eq!(mapped.port(), engine.local_addr().port());
        assert!(!udp.ipv6.ok);
        assert_eq!(udp.ipv6.error.as_deref(), Some("无该族 STUN 目标"));
        assert_eq!(stun_report.targets, 2);
        assert_eq!(stun_report.nat, "easy");
        assert!(rtt.is_some());
    }
}
