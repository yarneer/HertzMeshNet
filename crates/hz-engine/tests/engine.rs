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
    /// 有值时 `establish` 交出这个内存 TUN（测试经它收发明文 IP 包）。
    tun: Option<Arc<ChanTun>>,
}

/// 内存 TUN：测试往 `to_engine` 塞包 = 系统写进 TUN；引擎写回的包进 `from_engine`。
struct ChanTun {
    to_engine: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    from_engine: mpsc::Sender<Vec<u8>>,
}

impl TunIo for ChanTun {
    fn send_packet<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let _ = self.from_engine.send(packet.to_vec()).await;
            Ok(())
        })
    }

    fn recv_packet<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<usize>> + Send + 'a>>
    {
        Box::pin(async move {
            match self.to_engine.lock().await.recv().await {
                Some(packet) => {
                    buf[..packet.len()].copy_from_slice(&packet);
                    Ok(packet.len())
                }
                None => std::future::pending().await,
            }
        })
    }
}

impl FakePlatform {
    fn new() -> Arc<Self> {
        let (net_tx, _) = tokio::sync::broadcast::channel(64);
        Arc::new(Self {
            established: StdMutex::new(Vec::new()),
            protected: StdMutex::new(Vec::new()),
            net_tx,
            system_dns: vec!["192.0.2.53".parse().unwrap()],
            tun: None,
        })
    }

    /// 带内存 TUN 的假平台，返回 (平台, 往 TUN 写包的端, 读引擎回包的端)。
    fn with_tun() -> (Arc<Self>, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let (net_tx, _) = tokio::sync::broadcast::channel(64);
        let (to_engine_tx, to_engine_rx) = mpsc::channel(16);
        let (from_engine_tx, from_engine_rx) = mpsc::channel(16);
        let platform = Arc::new(Self {
            established: StdMutex::new(Vec::new()),
            protected: StdMutex::new(Vec::new()),
            net_tx,
            system_dns: vec![],
            tun: Some(Arc::new(ChanTun {
                to_engine: tokio::sync::Mutex::new(to_engine_rx),
                from_engine: from_engine_tx,
            })),
        });
        (platform, to_engine_tx, from_engine_rx)
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
        match &self.tun {
            Some(tun) => Ok(tun.clone()),
            None => anyhow::bail!("fake platform has no tun (drain mode)"),
        }
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
    // keep()：coord 的 SQLite 在测试进程外存活到 shutdown，目录不能随
    // TempDir 提前删除（unlink 后建 WAL/SHM 会偶发存储错误）。
    let store_path: PathBuf = dir.keep().join("coord.db");
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

/// keepalive 档位（#98 规格 §5.3）：EngineConfig 注入 WireGuard persistent
/// keepalive 与 coord HTTP/2 keepalive——桌面缺省 8s / 20s，Android 25s / 60s。
#[tokio::test]
async fn keepalive_tiers_from_engine_config_apply() {
    let _serial = SERIALIZE
        .get_or_init(tokio::sync::Mutex::default)
        .lock()
        .await;
    let platform = FakePlatform::new();
    let dir = tempfile::tempdir().unwrap();
    let android = EngineConfig {
        wg_keepalive_secs: 25,
        coord_keepalive_secs: 60,
        ..EngineConfig::default()
    };
    let engine = Engine::start(
        android,
        EngineHooks::default(),
        platform,
        dir.path().to_path_buf(),
    )
    .await
    .unwrap();
    assert_eq!(hz_core::wire::persistent_keepalive_secs(), 25);
    assert_eq!(hz_core::coord_client::http2_keepalive_secs(), 60);
    drop(engine);

    // 桌面缺省：0 = 8s / 20s。
    let platform = FakePlatform::new();
    let dir = tempfile::tempdir().unwrap();
    Engine::start(
        EngineConfig::default(),
        EngineHooks::default(),
        platform,
        dir.path().to_path_buf(),
    )
    .await
    .unwrap();
    assert_eq!(hz_core::wire::persistent_keepalive_secs(), 8);
    assert_eq!(hz_core::coord_client::http2_keepalive_secs(), 20);
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

/// Android 转发模式下系统发往 dns_v4:53 的查询以 IP 包从 TUN 读出：引擎须
/// 就地应答并把回包写回 TUN（而不是交给 WireGuard 丢掉——那会让手机上全部
/// 域名解析失败）。后缀内未知名 NXDOMAIN；后缀外走转发，上游列表为空时
/// SERVFAIL（证明进了转发分支，而非桌面的 REFUSED）。
#[tokio::test]
async fn dns_queries_read_from_tun_are_answered_back_into_tun() {
    let _serial = SERIALIZE
        .get_or_init(tokio::sync::Mutex::default)
        .lock()
        .await;
    let (coord, auth_key, coord_addr) = in_process_coord().await;
    let (platform, to_tun, mut from_tun) = FakePlatform::with_tun();
    let dir = tempfile::tempdir().unwrap();
    let config = EngineConfig {
        bind_egress: true,
        dns_forward: true,
        ..EngineConfig::default()
    };
    let engine = Engine::start(
        config,
        EngineHooks::default(),
        platform.clone(),
        dir.path().to_path_buf(),
    )
    .await
    .unwrap();
    engine
        .handle_request(Request::new(
            1,
            "up",
            serde_json::json!({ "auth_key": auth_key, "coord_addr": coord_addr }),
        ))
        .await
        .expect("up 应成功");
    eventually(10, || !platform.established.lock().unwrap().is_empty()).await;
    let dns_v4 = platform.established.lock().unwrap()[0].dns_v4;

    let ask = |id: u16, labels: &[&[u8]]| {
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in labels {
            payload.push(label.len() as u8);
            payload.extend_from_slice(label);
        }
        payload.extend_from_slice(&[0, 0, 1, 0, 1]);
        let mut packet = vec![0x45, 0];
        packet.extend_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 1, 0, 0, 64, 17, 0, 0, 100, 96, 0, 9]);
        packet.extend_from_slice(&dns_v4.octets());
        packet.extend_from_slice(&42000u16.to_be_bytes());
        packet.extend_from_slice(&53u16.to_be_bytes());
        packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(&payload);
        packet
    };
    let mut reply_for = async |packet: Vec<u8>| {
        to_tun.send(packet).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), from_tun.recv())
            .await
            .expect("引擎应把 DNS 应答写回 TUN")
            .unwrap()
    };

    let reply = reply_for(ask(31, &[b"ghost", b"hznet", b"internal"])).await;
    assert_eq!(&reply[12..16], &dns_v4.octets(), "回包源 = dns_v4");
    assert_eq!(&reply[16..20], &[100, 96, 0, 9], "回包目的 = 查询方");
    assert_eq!(u16::from_be_bytes([reply[22], reply[23]]), 42000);
    assert_eq!(
        u16::from_be_bytes([reply[28], reply[29]]),
        31,
        "query id 回显"
    );
    assert_eq!(reply[31] & 0x0f, 3, "后缀内未知名 NXDOMAIN");

    let reply = reply_for(ask(32, &[b"example", b"com"])).await;
    assert_eq!(u16::from_be_bytes([reply[28], reply[29]]), 32);
    assert_eq!(
        reply[31] & 0x0f,
        2,
        "后缀外进转发分支；上游列表为空回 SERVFAIL"
    );

    drop(engine);
    coord.shutdown();
    coord.terminated().await;
}
