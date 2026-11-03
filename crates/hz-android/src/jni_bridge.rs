//! JNI 胶水（`cfg(target_os = "android")`）：Kotlin `EngineBridge` 的导出函数
//! 与 Rust → Kotlin 回调（establish / protect）。Kotlin 侧接口见
//! `clients/android/app/src/main/java/dev/hznet/android/engine/EngineBridge.kt`。
//!
//! 线程模型：JNI 导出函数在调用线程上执行；引擎跑在本 crate 自建的
//! tokio 运行时上（`start` 建、`stop` 拆）。Platform 回调经
//! `JavaVM::attach_current_thread` 回到 JVM。
//!
//! 全局状态一个锁：`STATE { runtime, platform }`。platform 独立于 runtime
//! 存放——`onNetworkChanged` 在引擎尚未建好 / 已停止时也会到达，物理网络
//! 的 DNS 列表要跟得上。

use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::Arc;

use jni::objects::{JClass, JObject, JString};
use jni::sys::{JNI_TRUE, jboolean};
use jni::{JNIEnv, JavaVM};
use tokio::sync::mpsc;

use hz_core::netwatch::NetEvent;
use hz_core::tun::TunIo;
use hz_engine::{Platform, TunSpec};

use crate::{AndroidConfigJson, RUNTIME, Runtime, android_config_from_json, member_request_gate};

/// 运行中的引擎 + 它的 tokio 运行时（stop 时整体拆除）。
pub(crate) struct AndroidRuntime {
    pub engine: Arc<hz_engine::Engine>,
    pub rt: Arc<tokio::runtime::Runtime>,
}

/// 平台对象（establish / protect 回调 + Kotlin 网络推送的落点）。
pub(crate) struct AndroidPlatform {
    vm: JavaVM,
    platform: jni::objects::GlobalRef,
    net_tx: tokio::sync::broadcast::Sender<NetEvent>,
    system_dns: std::sync::RwLock<Vec<IpAddr>>,
}

// GlobalRef 在 jni 0.21 是 Send+Sync；跨线程持有是它的用途。
unsafe impl Send for AndroidPlatform {}
unsafe impl Sync for AndroidPlatform {}

impl AndroidPlatform {
    pub(crate) fn new(vm: JavaVM, platform: jni::objects::GlobalRef) -> Self {
        let (net_tx, _) = tokio::sync::broadcast::channel(64);
        Self {
            vm,
            platform,
            net_tx,
            system_dns: std::sync::RwLock::new(Vec::new()),
        }
    }

    pub(crate) fn note_network(&self, servers: Vec<IpAddr>) {
        *self.system_dns.write().expect("system dns poisoned") = servers;
        let _ = self.net_tx.send(NetEvent::EgressChanged);
    }

    fn call_establish(&self, spec_json: String) -> anyhow::Result<RawFd> {
        let mut env = self.vm.attach_current_thread()?;
        let jconfig: JString = env.new_string(&spec_json)?;
        let value = env.call_method(
            self.platform.as_ref(),
            "establish",
            "(Ljava/lang/String;)I",
            &[jni::objects::JValue::Object(&jconfig)],
        )?;
        let fd = value.i()?;
        anyhow::ensure!(fd >= 0, "Kotlin establish 返回了无效 fd：{fd}");
        Ok(fd as RawFd)
    }

    fn call_protect(&self, fd: RawFd) -> bool {
        let Ok(mut env) = self.vm.attach_current_thread() else {
            return false;
        };
        env.call_method(
            self.platform.as_ref(),
            "protect",
            "(I)Z",
            &[jni::objects::JValue::Int(fd as i32)],
        )
        .and_then(|value| value.z())
        .unwrap_or(false)
    }
}

impl Platform for AndroidPlatform {
    /// Kotlin 用 VpnService.Builder 建立 TUN（只路由 network_cidr 与 ULA
    /// 前缀、DNS 为 dns_v4，规格 §5.1），返回 detach 后的 fd。
    fn establish(&self, spec: TunSpec) -> anyhow::Result<Arc<dyn TunIo>> {
        let spec_json = serde_json::json!({
            "ipv4": spec.ipv4.to_string(),
            "ipv6": spec.ipv6.to_string(),
            "v4_cidr": spec.v4_cidr,
            "ula_prefix": hz_core::tun::ula_prefix48(spec.ipv6),
            "dns_v4": spec.dns_v4.to_string(),
            "mtu": spec.mtu,
        });
        let fd = self.call_establish(spec_json.to_string())?;
        Ok(Arc::new(FdTun::from_raw_fd(fd)))
    }

    fn protect(&self, fd: RawFd) -> bool {
        self.call_protect(fd)
    }

    fn net_events(&self) -> mpsc::Receiver<NetEvent> {
        // 恢复序列专用一条 mpsc；broadcast 允许未来更多消费者。
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
        self.system_dns.read().expect("system dns poisoned").clone()
    }
}

/// VpnService 的 TUN fd 读写端：原始 IP 包，无长度前缀（与 Linux TUN 的
/// IFF_NO_PI 相同成帧）。
struct FdTun {
    fd: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
}

impl FdTun {
    fn from_raw_fd(fd: RawFd) -> Self {
        // 所有权移交：Kotlin establish 返回的 fd 已 detach，归本端独占；
        // drop（数据面拆除）时关闭 fd。
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        Self {
            fd: tokio::io::unix::AsyncFd::new(owned).expect("TUN fd 可注册为异步"),
        }
    }
}

impl TunIo for FdTun {
    fn send_packet<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            loop {
                let mut guard = self.fd.writable().await?;
                match guard.try_io(|fd| write_all_raw(fd.get_ref().as_raw_fd(), packet)) {
                    Ok(result) => {
                        result?;
                        return Ok(());
                    }
                    Err(_would_block) => continue,
                }
            }
        })
    }

    fn recv_packet<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<usize>> + Send + 'a>>
    {
        Box::pin(async move {
            loop {
                let mut guard = self.fd.readable().await?;
                match guard.try_io(|fd| read_raw(fd.get_ref().as_raw_fd(), buf)) {
                    Ok(result) => return result,
                    Err(_would_block) => continue,
                }
            }
        })
    }
}

fn write_all_raw(fd: RawFd, packet: &[u8]) -> std::io::Result<()> {
    let mut written = 0usize;
    while written < packet.len() {
        let n = unsafe {
            libc::write(
                fd,
                packet[written..].as_ptr().cast(),
                packet.len() - written,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        written += n as usize;
    }
    Ok(())
}

fn read_raw(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// tracing 初始化（一次）：logcat + 环形缓冲双写（规格 §6）。
fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let ring = crate::ring_log().clone();
        struct Sink(Arc<crate::RingLog>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let line = String::from_utf8_lossy(buf);
                let line = line.trim_end();
                android_log(line);
                self.0.push_line(line.to_string());
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
            type Writer = Sink;
            fn make_writer(&'a self) -> Self::Writer {
                Sink(self.0.clone())
            }
        }
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_target(false)
            .with_ansi(false)
            .with_writer(Sink(ring))
            .try_init();
    });
}

/// 写 logcat（liblog 的 __android_log_write，INFO 级，tag=hznet）。
fn android_log(line: &str) {
    const ANDROID_LOG_INFO: i32 = 4;
    unsafe {
        static NAME: &[u8] = b"hznet\0";
        let mut with_nul: Vec<u8> = line.as_bytes().to_vec();
        with_nul.push(0);
        libc::__android_log_write(
            ANDROID_LOG_INFO,
            NAME.as_ptr().cast(),
            with_nul.as_ptr().cast(),
        );
    }
}

// ---- Kotlin → Rust 导出函数 ----
//
// 约定：除了 request 返回 JSON 字符串，其余以异常表达失败（Kotlin 侧
// `check(env.exception_check())` 后转成自己的错误类型）。

fn throw(env: &JNIEnv, message: &str) {
    // 抛 java.lang.IllegalStateException；消息截断防超长。
    let message: String = message.chars().take(500).collect();
    let _ = env.throw_new("java/lang/IllegalStateException", message);
}

/// 当前运行时快照（锁内克隆，立刻放锁）。
fn with_runtime<T>(f: impl FnOnce(&AndroidRuntime) -> T) -> Option<T> {
    let guard = RUNTIME.blocking_lock();
    guard.as_ref().map(f)
}

/// 平台槽（start 建好、进程存活期内不换）。
static PLATFORM: std::sync::OnceLock<Arc<AndroidPlatform>> = std::sync::OnceLock::new();

/// `start(configJson, platform) -> boolean`：建 tokio 运行时并启动引擎。
/// 已在运行时直接返回 true（Kotlin 状态机保证 stop 之后再 start）。
#[no_mangle]
pub unsafe extern "C" fn Java_dev_hznet_android_engine_EngineBridge_start(
    env: JNIEnv,
    _class: JClass,
    config_json: JString,
    platform: JObject,
) -> jboolean {
    if start_impl(&env, &config_json, &platform).is_ok() {
        JNI_TRUE
    } else {
        false as jboolean
    }
}

fn start_impl(env: &JNIEnv, config_json: &JString, platform: &JObject) -> anyhow::Result<()> {
    let config_text: String = env.get_string(config_json)?.into();
    let json: serde_json::Value = serde_json::from_str(&config_text)?;
    let android_config: AndroidConfigJson = serde_json::from_value(json)?;
    let state_dir = std::path::PathBuf::from(android_config.state_dir.trim_end_matches('/'));
    let config = android_config_from_json(&android_config)?;

    init_tracing();

    let vm = env.get_java_vm()?;
    let platform_ref = env.new_global_ref(platform)?;
    let android_platform = Arc::new(AndroidPlatform::new(vm, platform_ref));
    // 首次 start 登记平台（onNetworkChanged 的落点）；重启引擎复用旧平台。
    let android_platform = match PLATFORM.set(android_platform.clone()) {
        Ok(()) => android_platform,
        Err(existing) => existing.clone(),
    };

    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?,
    );
    let hooks = crate::android_hooks(crate::ring_log().clone());
    let engine = rt.block_on(hz_engine::Engine::start(
        config,
        hooks,
        android_platform,
        state_dir,
    ))?;
    tracing::info!("hz-android engine started");

    let mut guard = RUNTIME.blocking_lock();
    if guard.is_some() {
        return Ok(()); // 已在运行。
    }
    // 把引擎放进 lib.rs 的 RUNTIME（request/subscribe 共用）。
    *guard = Some(Runtime {
        engine: engine.clone(),
        shutdown: {
            let (tx, _rx) = tokio::sync::watch::channel(false);
            tx
        },
    });
    drop(guard);
    // 真正的运行时本体存这里，stop 时整体拆除。
    *RUNTIME_HANDLE.lock().expect("runtime handle poisoned") = Some(rt);
    Ok(())
}

/// 运行时本体（与 lib.rs 的 RUNTIME 分开存放：那个只放引擎句柄）。
static RUNTIME_HANDLE: std::sync::Mutex<Option<Arc<tokio::runtime::Runtime>>> =
    std::sync::Mutex::new(None);

/// `stop()`：停数据面与运行时（引擎任务随运行时拆除结束）。幂等。
#[no_mangle]
pub unsafe extern "C" fn Java_dev_hznet_android_engine_EngineBridge_stop(
    _env: JNIEnv,
    _class: JClass,
) {
    let rt = RUNTIME_HANDLE
        .lock()
        .expect("runtime handle poisoned")
        .take();
    *RUNTIME.blocking_lock() = None;
    if let Some(rt) = rt {
        tracing::info!("hz-android engine stopping");
        // 给数据面拆除留 3 秒（TUN fd 随任务 drop 关闭），然后硬停。
        rt.shutdown_timeout(std::time::Duration::from_secs(3));
    }
}

/// `request(json) -> json`：成员档请求分发。封套 `{"method","params"}` →
/// `{"ok":true,"result":…}` / `{"ok":false,"error":"…"}`。
#[no_mangle]
pub unsafe extern "C" fn Java_dev_hznet_android_engine_EngineBridge_request(
    env: JNIEnv,
    _class: JClass,
    request_json: JString,
) -> JString {
    let Ok(text): Result<String, _> = env.get_string(&request_json).map(Into::into) else {
        let _ = env.throw_new(
            "java/lang/IllegalArgumentException",
            "请求必须是 JSON 字符串",
        );
        return env
            .new_string("{\"ok\":false,\"error\":\"bad request\"}")
            .expect("JVM 字符串分配");
    };
    let reply = route_request(&text);
    env.new_string(&reply).expect("JVM 字符串分配")
}

fn route_request(request_text: &str) -> String {
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(request_text);
    let request = match parsed {
        Ok(value) => value,
        Err(error) => {
            return serde_json::json!({
                "ok": false,
                "error": format!("请求 JSON 无效：{error}"),
            })
            .to_string();
        }
    };
    let method = request
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let params = request
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    if let Err(error) = member_request_gate(&method, &params) {
        return serde_json::json!({ "ok": false, "error": error }).to_string();
    }
    let outcome = with_runtime(|runtime| {
        let rt = RUNTIME_HANDLE
            .lock()
            .expect("runtime handle poisoned")
            .clone();
        (runtime.engine.clone(), rt)
    });
    let Some((engine, Some(rt))) = outcome else {
        return serde_json::json!({ "ok": false, "error": "引擎未运行（先 start）" }).to_string();
    };
    let request = hz_core::ipc::Request::new(0, &method, params);
    match rt.block_on(engine.handle_request(request)) {
        Ok(result) => serde_json::json!({ "ok": true, "result": result }).to_string(),
        Err(error) => serde_json::json!({ "ok": false, "error": error }).to_string(),
    }
}

/// `subscribe(callback)`：推送与 IPC `subscribe` 同形状的快照（含
/// desired_state），节流与心跳规则相同——直接复用引擎的订阅循环，
/// 逐条 `Response` 序列化为 JSON 行回调给 Kotlin。
#[no_mangle]
pub unsafe extern "C" fn Java_dev_hznet_android_engine_EngineBridge_subscribe(
    env: JNIEnv,
    _class: JClass,
    callback: JObject,
) {
    let Ok(vm) = env.get_java_vm() else { return };
    let Ok(callback) = env.new_global_ref(callback) else {
        return;
    };
    let Some(rt) = RUNTIME_HANDLE
        .lock()
        .expect("runtime handle poisoned")
        .clone()
    else {
        return;
    };
    let Some(engine) = with_runtime(|runtime| runtime.engine.clone()) else {
        return;
    };
    let (tx, mut rx) = mpsc::channel::<hz_core::ipc::Response>(16);
    rt.spawn(hz_engine::subscribe_loop(engine, 0, tx));
    rt.spawn(async move {
        while let Some(response) = rx.recv().await {
            let text = serde_json::to_string(&response).unwrap_or_default();
            if !push_snapshot(&vm, &callback, &text) {
                return; // Kotlin 回调已释放（订阅方退出）。
            }
        }
    });
}

fn push_snapshot(vm: &JavaVM, callback: &jni::objects::GlobalRef, text: &str) -> bool {
    let Ok(mut env) = vm.attach_current_thread() else {
        return false;
    };
    let Ok(jtext) = env.new_string(text) else {
        return false;
    };
    env.call_method(
        callback.as_ref(),
        "onSnapshot",
        "(Ljava/lang/String;)V",
        &[jni::objects::JValue::Object(&jtext)],
    )
    .is_ok()
}

/// `onNetworkChanged(dnsServersJson)`：Kotlin 推送物理网络变化与当前 DNS
/// 服务器（ConnectivityManager.NetworkCallback 驱动，规格 §6），喂给
/// net_events（恢复序列）与 system_dns（转发上游，#98）。
#[no_mangle]
pub unsafe extern "C" fn Java_dev_hznet_android_engine_EngineBridge_onNetworkChanged(
    env: JNIEnv,
    _class: JClass,
    dns_servers_json: JString,
) {
    let Ok(text): Result<String, _> = env.get_string(&dns_servers_json).map(Into::into) else {
        return;
    };
    let servers: Vec<IpAddr> = serde_json::from_str::<Vec<String>>(&text)
        .map(|list| list.iter().filter_map(|s| s.parse().ok()).collect())
        .unwrap_or_default();
    if let Some(platform) = PLATFORM.get() {
        platform.note_network(servers);
    }
}

/// `desiredState() -> String`：UI 七态判定读 Desired State（快照里也有，
/// 这里给 onRevoke 等非订阅时点的即时读取）。
#[no_mangle]
pub unsafe extern "C" fn Java_dev_hznet_android_engine_EngineBridge_desiredState(
    env: JNIEnv,
    _class: JClass,
) -> JString {
    let state = with_runtime(|runtime| runtime.engine.desired_state_str().to_string())
        .unwrap_or_else(|| "down".to_string());
    env.new_string(&state).expect("JVM 字符串分配")
}

/// `ringLogTail() -> json`：诊断预览（环形缓冲快照，脱敏后）。
#[no_mangle]
pub unsafe extern "C" fn Java_dev_hznet_android_engine_EngineBridge_ringLogTail(
    env: JNIEnv,
    _class: JClass,
) -> JString {
    let lines = crate::ring_log().tail_lines();
    let text = serde_json::to_string(&lines).unwrap_or_else(|_| "[]".to_string());
    env.new_string(&text).expect("JVM 字符串分配")
}
