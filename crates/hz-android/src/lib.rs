//! hz-android：JNI 桥（MA-5，规格 §6）。引擎运行在 VpnService 进程内，
//! Kotlin 经本 crate 的导出函数驱动，平台能力经回调回到 Kotlin：
//!
//! | 方向 | 接口 |
//! |---|---|
//! | Kotlin → Rust | `start(configJson, platform)` / `request(json)` / `subscribe(cb)` / `stop()` / `onNetworkChanged(dnsServersJson)` |
//! | Rust → Kotlin | `platform.establish(tunSpecJson) -> fd` / `platform.protect(fd) -> bool` |
//!
//! `request` 固定按成员档执行：管理档方法（带 Auth Key 的 `up`、`policy_*`、
//! `authkey_*`、`invite_*`、`node_*`）一律拒绝（见 [`member_request_gate`]，
//! host 侧单测覆盖）。日志经 tracing 同时写 logcat 与 2000 行内存环形缓冲，
//! `diagnostics` 的 log_tail 取自该缓冲。
//!
//! 本 crate 的纯逻辑（成员档闸门、配置 JSON、环形缓冲）在 host 上单测；
//! JNI 胶水在 `cfg(target_os = "android")` 下编译。

pub mod ring;

use std::sync::Arc;

use hz_engine::{EngineConfig, EngineHooks, LogTailFn};
use serde_json::Value;

/// Kotlin 侧的日志环形缓冲（2000 行，规格 §6）。
pub use ring::RingLog;

/// 成员档闸门：Client App 只服务普通 User，管理方法一律拒绝
/// （规格 §6；策略同 macOS Client App）。返回 Err(原因) 即拒绝。
pub fn member_request_gate(method: &str, params: &Value) -> Result<(), String> {
    const ADMIN_METHODS: &[&str] = &[
        "policy_push",
        "policy_get",
        "policy_rollback",
        "authkey_create",
        "authkey_revoke",
        "invite_create",
        "invite_list",
        "invite_revoke",
        "node_list",
        "node_rename",
        "node_delete",
        "node_revoke",
    ];
    if ADMIN_METHODS.contains(&method) {
        return Err(format!(
            "管理操作（{method}）仅在 Admin Console 与 hz CLI 提供，App 不支持"
        ));
    }
    // `up` 本身可用，但 Auth Key 注册是 Admin 发放渠道——App 只走
    // 邀请码与浏览器登录（无 Auth Key 输入，规格 §8）。
    if method == "up" {
        let auth_key = params.get("auth_key").and_then(Value::as_str).unwrap_or("");
        if !auth_key.is_empty() {
            return Err("App 不支持 Auth Key 注册，请使用浏览器登录或邀请码".to_string());
        }
    }
    Ok(())
}

/// Kotlin 传入的配置 JSON（EngineConfig 的可序列化投影；缺省字段走
/// `EngineConfig::default`）。Android 档位缺省与桌面不同（#98 规格 §5.3），
/// 在 [`android_config_from_json`] 里补齐。
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct AndroidConfigJson {
    pub state_dir: String,
    pub coord_addr: Option<String>,
    pub relay_addr: Option<String>,
    pub relay_ca_pem: Option<String>,
    pub stun_addrs: Option<Vec<String>>,
    pub dns_suffix: Option<String>,
    pub node_name: Option<String>,
}

/// 配置 JSON → EngineConfig（Android 档位：DNS 转发开、keepalive 25s/60s）。
/// `node_name` 不进 EngineConfig——它作为 `up` 的注册参数传给 coord（Kotlin
/// 引导页预填 `Build.MODEL` 规范化结果，#100）。
pub fn android_config_from_json(config: &AndroidConfigJson) -> anyhow::Result<EngineConfig> {
    if config.state_dir.trim().is_empty() {
        anyhow::bail!("缺少 state_dir（App 的 filesDir/hznet）");
    }
    Ok(EngineConfig {
        coord_addr: config.coord_addr.clone(),
        node_name: config
            .node_name
            .clone()
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty()),
        relay_addr: config.relay_addr.clone(),
        relay_ca_pem: config.relay_ca_pem.clone(),
        stun_addrs: config.stun_addrs.clone(),
        dns_suffix: config
            .dns_suffix
            .clone()
            .unwrap_or_else(|| hz_core::dns::DEFAULT_DNS_SUFFIX.to_string()),
        // Android（#98 规格 §5.2/§5.3）：转发模式 + 移动端 keepalive 档位。
        dns_forward: true,
        wg_keepalive_secs: 25,
        coord_keepalive_secs: 60,
        bind_egress: false,
        ..EngineConfig::default()
    })
}

/// 组装 Android 侧的引擎钩子：log_tail 取环形缓冲。
pub fn android_hooks(log: Arc<RingLog>) -> EngineHooks {
    let log_tail: LogTailFn = Arc::new(move || {
        let lines = log.tail_lines();
        let count = lines.len();
        (
            lines,
            Some(format!("最近 {count} 行（内存环形缓冲，已脱敏）")),
        )
    });
    EngineHooks {
        aux_tasks: None,
        on_dataplane_down: Vec::new(),
        log_tail: Some(log_tail),
    }
}

pub(crate) static RING_LOG: std::sync::OnceLock<Arc<RingLog>> = std::sync::OnceLock::new();

/// 环形缓冲的单例入口（tracing layer 与 log_tail 共用）。
pub fn ring_log() -> &'static Arc<RingLog> {
    RING_LOG.get_or_init(|| Arc::new(RingLog::new(ring::RING_CAPACITY)))
}

#[cfg(target_os = "android")]
mod jni_bridge;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn gate(method: &str, params: Value) -> Result<(), String> {
        member_request_gate(method, &params)
    }

    #[test]
    fn admin_methods_are_rejected() {
        for method in [
            "policy_push",
            "policy_get",
            "policy_rollback",
            "authkey_create",
            "authkey_revoke",
            "invite_create",
            "invite_list",
            "invite_revoke",
            "node_list",
            "node_rename",
            "node_delete",
            "node_revoke",
        ] {
            let denied = gate(method, json!({}));
            assert!(denied.is_err(), "{method} 应被拒绝");
            assert!(
                denied.unwrap_err().contains("管理操作"),
                "{method} 拒绝原因应可读"
            );
        }
    }

    #[test]
    fn up_with_auth_key_is_rejected_but_member_paths_pass() {
        assert!(gate("up", json!({ "auth_key": "hznet.xxxx" })).is_err());
        // 邀请码与浏览器登录（无 auth_key）可用。
        assert!(gate("up", json!({ "invite_code": "HZ-ABCD-EFGH" })).is_ok());
        assert!(gate("up", json!({})).is_ok());
        // 其余成员方法不受影响。
        assert!(gate("status", json!({})).is_ok());
        assert!(gate("ping", json!({ "node": "db-1" })).is_ok());
        assert!(gate("netcheck", json!({})).is_ok());
        assert!(gate("diagnostics", json!({})).is_ok());
        assert!(gate("down", json!({})).is_ok());
        assert!(gate("login_poll", json!({})).is_ok());
    }

    #[test]
    fn android_config_defaults_to_mobile_tiers() {
        let config = android_config_from_json(&AndroidConfigJson {
            state_dir: "/data/…/files/hznet".into(),
            ..AndroidConfigJson::default()
        })
        .unwrap();
        assert!(config.dns_forward, "Android 默认开 DNS 转发");
        assert_eq!(config.wg_keepalive_secs, 25);
        assert_eq!(config.coord_keepalive_secs, 60);
        assert!(
            !config.bind_egress,
            "无 SO_BINDTODEVICE，protect 走 VpnService"
        );
    }

    #[test]
    fn android_config_requires_state_dir() {
        assert!(android_config_from_json(&AndroidConfigJson::default()).is_err());
    }
}
