//! hzd 守护进程（桌面组合根）：把平台无关的 [`hz_engine::Engine`] 与桌面
//! [`platform::DesktopPlatform`] 组装起来，经 UDS IPC 对 `hz` CLI / Client App
//! 服务。桌面专属部分都在这里：IPC 服务器、launchd / systemd 集成、路由
//! 守护与 VPN 冲突检测、系统 DNS 接入、Port Map；编排逻辑在 hz-engine。
//! 环境变量（`HZD_*` / `HZNET_DNS_SUFFIX`）在本 crate 解析成
//! [`hz_engine::EngineConfig`]，引擎内不读环境变量（ADR-0013）。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use hz_core::ipc::{self, Handler};
use hz_engine::{AuxCtx, Engine, EngineConfig, EngineHooks};

pub mod diagnostics;
pub mod dns;
pub mod launchd;
pub mod platform;
pub mod portmap;

/// status 快照里的对端视图；契约 fixture 测试经本路径引用。
pub use hz_engine::MapPeer;
/// hzd 的 ping 数据面（探针拦截）在引擎内；测试经本路径引用。
pub use hz_engine::ping;

/// 环境变量 → 引擎配置（ADR-0013：解析只发生在 hzd，引擎不读环境变量）。
/// 未设置的项走 [`EngineConfig::default`] 的桌面缺省。
pub fn config_from_env() -> EngineConfig {
    let relay_ca_pem = std::env::var("HZD_RELAY_CA_PATH")
        .ok()
        .filter(|path| !path.is_empty())
        .and_then(|path| match std::fs::read_to_string(&path) {
            Ok(pem) => Some(pem),
            Err(error) => {
                tracing::warn!(%path, %error, "read relay CA failed, using system roots");
                None
            }
        });
    EngineConfig {
        coord_addr: std::env::var("HZD_COORD_ADDR")
            .ok()
            .filter(|v| !v.is_empty()),
        wg_port: std::env::var("HZD_WG_PORT")
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(0),
        bind_egress: std::env::var("HZD_BIND_EGRESS").ok().as_deref() != Some("0"),
        relay_addr: std::env::var("HZD_RELAY_ADDR")
            .ok()
            .filter(|v| !v.is_empty()),
        relay_ca_pem,
        stun_addrs: std::env::var("HZD_STUN_ADDR").ok().map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|target| !target.is_empty())
                .map(str::to_string)
                .collect()
        }),
        v4_cidr: std::env::var("HZD_V4_CIDR").ok().filter(|v| !v.is_empty()),
        force_relay: std::env::var("HZD_FORCE_RELAY").ok().as_deref() == Some("1"),
        dns_suffix: hz_core::dns::dns_suffix_from(
            std::env::var("HZNET_DNS_SUFFIX").ok().as_deref(),
        ),
        bootstrap_dns: std::env::var("HZD_BOOTSTRAP_DNS")
            .ok()
            .filter(|v| !v.is_empty()),
        portmap_enabled: std::env::var("HZD_PORTMAP").ok().as_deref() != Some("0"),
        portmap_gateway: std::env::var("HZD_PORTMAP_GATEWAY")
            .ok()
            .filter(|v| !v.trim().is_empty()),
        dns_resolvconf_fallback: matches!(
            std::env::var("HZD_DNS_RESOLVCONF_FALLBACK").as_deref(),
            Ok("1") | Ok("true")
        ),
        // 桌面不开 DNS 转发（分域接管）也不改 keepalive 档位（#98）；
        // Node Name 取本机主机名（node_name: None）。
        dns_forward: false,
        wg_keepalive_secs: 0,
        coord_keepalive_secs: 0,
        node_name: None,
    }
}

/// 组装并启动 hzd：引擎 + 桌面平台 + UDS IPC（status/ping/netcheck/diagnostics/
/// up/down/subscribe 与管理方法）。阻塞直到 IPC 服务器退出。
pub async fn run(state_dir: PathBuf, socket_path: PathBuf) -> anyhow::Result<()> {
    run_with(config_from_env(), state_dir, socket_path).await
}

/// [`run`] 的配置注入版（自定义部署 / 集成测试用）。
pub async fn run_with(
    config: EngineConfig,
    state_dir: PathBuf,
    socket_path: PathBuf,
) -> anyhow::Result<()> {
    let platform = Arc::new(platform::DesktopPlatform::new(
        config.dns_resolvconf_fallback,
    ));
    let portmap_gateway = config.portmap_gateway.clone();
    let portmap_enabled = config.portmap_enabled;
    let hooks = EngineHooks {
        aux_tasks: Some(Arc::new(move |ctx: &AuxCtx| {
            portmap::spawn_aux(ctx, portmap_enabled, portmap_gateway.clone())
        })),
        on_dataplane_down: vec![Arc::new(dns::deactivate)],
        log_tail: Some(Arc::new(diagnostics::collect_log_tail)),
    };
    let engine = Engine::start(config, hooks, platform, state_dir).await?;

    let handler: Handler = {
        let engine = engine.clone();
        Arc::new(move |request: ipc::Request| {
            let engine = engine.clone();
            Box::pin(async move { engine.handle_request(request).await })
        })
    };
    // subscribe（#83 / MC-3）：IPC 第一个流式方法，同一请求 id 下逐行推完整
    // status 快照；macOS / Android Client App 驱动 UI 的唯一数据源。
    let mut streams: HashMap<String, ipc::StreamHandler> = HashMap::new();
    let subscribe_engine = engine.clone();
    streams.insert(
        "subscribe".to_string(),
        ipc::stream_handler(move |request: ipc::Request, sender: ipc::ResponseSink| {
            let engine = subscribe_engine.clone();
            async move {
                hz_engine::subscribe_loop(engine, request.id, sender).await;
            }
        }),
    );
    ipc::serve_with(&socket_path, handler, Arc::new(streams)).await
}
