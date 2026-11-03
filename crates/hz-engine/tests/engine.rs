//! 引擎单元测试（ADR-0013 / #104）：`Platform` 假实现驱动编排引擎，断言
//! 外部可见行为——`establish` 收到的 `TunSpec`、外层 socket 是否被
//! `protect`、`net_events` 是否触发重绑与 Endpoint 重采。coord 用进程内
//! 真实实例（内存 SQLite + 回环端口），与 hzd 的 Seam B 同一拓扑。

use std::net::IpAddr;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, serve};
use hz_coord::store::Store;
use hz_core::ipc::Request;
use hz_core::netwatch::NetEvent;
use hz_core::tun::TunIo;
use hz_engine::{Engine, EngineConfig, EngineHooks, Platform, TunSpec};
use tokio::sync::mpsc;

/// 假平台：记录 `establish` 收到的规格与 `protect` 的 fd；`establish` 一律
/// 失败（测试机无 root），引擎按既有行为降级为纯控制面。事件流由测试注入。
struct FakePlatform {
    established: StdMutex<Vec<TunSpec>>,
    protected: StdMutex<Vec<RawFd>>,
    net_tx: tokio::sync::broadcast::Sender<NetEvent>,
    system_dns: Vec<IpAddr>,
}

impl FakePlatform {
    fn new() -> Arc<Self> {
        let (net_tx, _) = tokio::sync::broadcast::channel(64);
        Arc::new(Self {
            established: StdMutex::new(Vec::new()),
            protected: StdMutex::new(Vec::new()),
            net_tx,
            system_dns: vec!["192.0.2.53".parse().unwrap()],
        })
    }

    async fn push_event(&self, event: NetEvent) {
        let _ = self.net_tx.send(event);
    }

    /// 恢复任务的订阅是异步建立的（tokio 单线程测试运行时里推迟到让出点）。
    async fn wait_for_subscriber(&self) {
        for _ in 0..100 {
            if self.net_tx.receiver_count() > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("恢复任务未订阅平台事件流");
    }
}

impl Platform for FakePlatform {
    fn establish(&self, spec: TunSpec) -> anyhow::Result<Arc<dyn TunIo>> {
        self.established
            .lock()
            .expect("established poisoned")
            .push(spec);
        anyhow::bail!("fake platform has no tun (drain mode)")
    }

    fn protect(&self, fd: RawFd) -> bool {
        self.protected.lock().expect("protected poisoned").push(fd);
        true
    }

    fn net_events(&self) -> mpsc::Receiver<NetEvent> {
        let (tx, rx) = mpsc::channel(64);
        let mut sub = self.net_tx.subscribe();
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                }
            }
        });
        rx
    }

    fn system_dns(&self) -> Vec<IpAddr> {
        self.system_dns.clone()
    }
}

/// 进程级钩子（socket protector、DNS 后缀）是全局的：测试之间串行执行，
/// 避免后装的 protector 抢走先启动引擎的 protect 记录。
static SERIALIZE: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

/// 进程级日志缓冲：subscriber 只能全局装一次（tokio 任务跨线程），全部
/// 测试共享一个缓冲；各测试断言自己的标记串，互不混淆。
fn captured_logs() -> Arc<StdMutex<String>> {
    static LOGS: std::sync::OnceLock<Arc<StdMutex<String>>> = std::sync::OnceLock::new();
    struct SharedWriter(Arc<StdMutex<String>>);
    impl std::io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_str(&String::from_utf8_lossy(buf));
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedWriter {
        type Writer = SharedWriter;
        fn make_writer(&'a self) -> Self::Writer {
            SharedWriter(self.0.clone())
        }
    }
    let logs = LOGS.get_or_init(|| Arc::new(StdMutex::new(String::new())));
    // 第一个调用者装全局 subscriber；后续（测试串行）忽略重复初始化。
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .with_writer(SharedWriter(logs.clone()))
        .try_init();
    logs.clone()
}

/// 进程内 coord（回环 + 内存库）+ 一个可用的 Auth Key。
async fn in_process_coord() -> (hz_coord::service::ServeHandle, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let store_path: PathBuf = dir.path().join("coord.db");
    let store = Store::open(&store_path, AddressConfig::default())
        .await
        .unwrap();
    let auth_key = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, true, &[])
        .await
        .unwrap();
    let coord = serve(ServeConfig::new(store, "127.0.0.1:0".parse().unwrap()))
        .await
        .unwrap();
    let addr = format!("http://{}", coord.local_addr);
    (coord, auth_key, addr)
}

/// 注册并拉起数据面，返回引擎与假平台。
async fn registered_engine(
    coord_addr: &str,
    auth_key: &str,
) -> (Arc<Engine>, Arc<FakePlatform>, tempfile::TempDir) {
    let platform = FakePlatform::new();
    let dir = tempfile::tempdir().unwrap();
    // bind_egress=true：WireGuard UDP socket 的创建走 Platform::protect
    // （假实现只记录 fd，不真的绑设备，无 root 环境可跑）。
    let config = EngineConfig {
        bind_egress: true,
        ..EngineConfig::default()
    };
    let state_dir = dir.path().to_path_buf();
    let engine = Engine::start(config, EngineHooks::default(), platform.clone(), state_dir)
        .await
        .unwrap();
    let up = engine
        .handle_request(Request::new(
            1,
            "up",
            serde_json::json!({ "auth_key": auth_key, "coord_addr": coord_addr }),
        ))
        .await
        .expect("up 应成功");
    assert!(up.get("node_id").is_some(), "up 应返回注册身份：{up}");
    (engine, platform, dir)
}

/// 轮询断言辅助：最多等 `secs` 秒，每 100ms 取一次。
async fn eventually<F>(secs: u64, mut probe: F)
where
    F: FnMut() -> bool,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        if probe() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("条件在 {secs} 秒内未满足");
}

/// establish 收到的 TunSpec：地址来自注册授予、段与 DNS 应答地址与 coord
/// 下发一致（引擎不得把别的网段交给平台，规格 §5.1）。
#[tokio::test]
async fn establish_receives_registered_addresses_network_and_dns() {
    let _serial = SERIALIZE
        .get_or_init(tokio::sync::Mutex::default)
        .lock()
        .await;
    let (coord, auth_key, coord_addr) = in_process_coord().await;
    let (engine, platform, _dir) = registered_engine(&coord_addr, &auth_key).await;

    eventually(10, || !platform.established.lock().unwrap().is_empty()).await;
    let specs = platform.established.lock().unwrap().clone();
    let spec = &specs[0];
    let status = engine.status_value().await.unwrap();
    let own_ipv4 = status["ipv4"]
        .as_str()
        .unwrap()
        .parse::<std::net::Ipv4Addr>()
        .unwrap();
    assert_eq!(spec.ipv4, own_ipv4, "TUN 地址 = 本机 Node Address");
    assert!(
        spec.ipv4 != std::net::Ipv4Addr::new(100, 96, 0, 53),
        "不得占用 DNS 应答地址"
    );
    assert_eq!(spec.v4_cidr, "100.96.0.0/16", "生效段 = coord 下发段");
    assert_eq!(
        spec.dns_v4,
        "100.96.0.53".parse::<std::net::Ipv4Addr>().unwrap(),
        "DNS 应答地址 = 注册响应携带值"
    );
    assert_eq!(spec.mtu, hz_core::tun::MTU);
    assert!(
        spec.ipv6.is_unicast_link_local() || spec.ipv6.to_string().starts_with("fd"),
        "ULA"
    );
    coord.shutdown();
    coord.terminated().await;
}

/// 引擎创建的外层 socket 都经过 Platform::protect：WireGuard UDP socket 在
/// bind_egress=true 时必经（protect 钩子装进 hz-core 的创建点）。
#[tokio::test]
async fn outer_sockets_go_through_platform_protect() {
    let _serial = SERIALIZE
        .get_or_init(tokio::sync::Mutex::default)
        .lock()
        .await;
    let (coord, auth_key, coord_addr) = in_process_coord().await;
    let (_engine, platform, _dir) = registered_engine(&coord_addr, &auth_key).await;

    eventually(10, || !platform.protected.lock().unwrap().is_empty()).await;
    let fds = platform.protected.lock().unwrap().clone();
    assert!(!fds.is_empty(), "WireGuard UDP socket 创建必须经过 protect");
    // 回环上的 coord 连接豁免（connect_bound 的既有规则）不算回归；这里只
    // 断言 protect 路径被走到且每次 fd 合法（≥0）。
    assert!(fds.iter().all(|fd| *fd >= 0));
    coord.shutdown();
    coord.terminated().await;
}

/// net_events 触发恢复序列：重绑（或其平台失败日志）与 Endpoint 重采上报。
/// 用可捕获日志的 subscriber 观察（"network change, recovering" 及其后的
/// rebind 日志），重采结果经 `netcheck` 的 endpoints 可见。
#[tokio::test]
async fn net_events_drive_rebind_and_endpoint_recollect() {
    let _serial = SERIALIZE
        .get_or_init(tokio::sync::Mutex::default)
        .lock()
        .await;
    let logs = captured_logs();

    let (coord, auth_key, coord_addr) = in_process_coord().await;
    let (engine, platform, _dir) = registered_engine(&coord_addr, &auth_key).await;

    // ClockJump 跳过快照去抖（测试机网络环境不变），恢复序列必执行。
    platform.wait_for_subscriber().await;
    platform.push_event(NetEvent::ClockJump).await;

    // 重绑的三个结局（在位改绑 / 重建 / 平台不支持——macOS）都算"重绑被触发"。
    let mut recovered = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        let text = logs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        recovered = text.contains("network change, recovering")
            && (text.contains("udp socket rebound")
                || text.contains("udp socket recreated")
                || text.contains("udp socket rebind failed"));
        if recovered {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        recovered,
        "恢复序列标记未出现；日志尾部：\n{}",
        logs.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .lines()
            .rev()
            .take(40)
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Endpoint 重采：恢复序列即时 collect_and_report，netcheck 的 endpoints
    // 反映共享槽（LAN 候选在测试环境通常可用；无候选的环境日志已覆盖上报
    // 尝试，这里以 netcheck 非空为强断言）。
    let mut endpoints_seen = false;
    for _ in 0..100 {
        let netcheck = engine
            .handle_request(Request::new(2, "netcheck", serde_json::json!({})))
            .await
            .expect("netcheck 应成功");
        if netcheck["endpoints"]
            .as_array()
            .is_some_and(|e| !e.is_empty())
        {
            endpoints_seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        endpoints_seen,
        "恢复序列应重采 Endpoint 并进入 netcheck 视图"
    );

    coord.shutdown();
    coord.terminated().await;
}
