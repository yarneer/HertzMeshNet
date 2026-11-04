//! #85 / MC-5：IPC 契约 fixture。Rust 测试把典型响应写进与平台无关的
//! `clients/fixtures/`（Swift 单测逐个解码；v0.5 Windows Client 复用）。
//!
//! 本测试**总是重写**文件（以代码里的定义为唯一事实源）；CI 在跑完本测试
//! 后用 `git diff --exit-code clients/fixtures` 校验无漂移——Rust 侧改了
//! IPC 字段而 fixture 没跟着改（或反之）都会在这里现形。
//!
//! 主体结构用真实类型序列化（`NodeStatus` / `MapPeer`），保证身份与对端
//! 字段名跟实现同步漂移；hzd 组装的附加字段（peers / desired_state /
//! dns_suffix / coord_addr / revoked / version_hint / diagnostics /
//! policy）以内容为准——serde_json 默认按键字母序输出，键序不构成契约
//! （Swift Codable 不依赖键序）。

use hz_core::status::{NodeStatus, RegisteredInfo};
use serde_json::{Value, json};

fn repo_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR = crates/hzd。
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn registered_info(name: &str, ipv4: &str, expires: Option<i64>) -> RegisteredInfo {
    RegisteredInfo {
        node_id: format!("n-{name}"),
        name: name.to_string(),
        ipv4: ipv4.to_string(),
        ipv6: "fd00:96::1".to_string(),
        tags: vec![],
        owner_user: Some("alice".to_string()),
        expires_at_unix: expires,
        network_cidr: Some("100.96.0.0/16".to_string()),
        dns_v4: Some("100.96.0.53".to_string()),
    }
}

fn peer_direct(name: &str, handshake_secs: u64) -> hzd::MapPeer {
    hzd::MapPeer {
        name: name.to_string(),
        ipv4: "100.96.0.2".to_string(),
        ipv6: "fd00:96::2".to_string(),
        endpoints: vec!["203.0.113.9:41001".to_string()],
        handshake_secs: Some(handshake_secs),
        path: Some("direct".to_string()),
        endpoint: Some("203.0.113.9:41001".to_string()),
        relay_reason: None,
    }
}

fn peer_relay(name: &str) -> Value {
    // relay_reason 现在是 hzd peers_view 的真实产出（与 Health Report 同一
    // 判定来源）；fixture 用真实 MapPeer 序列化，杜绝契约漂移。
    serde_json::to_value(hzd::MapPeer {
        name: name.to_string(),
        ipv4: "100.96.0.3".to_string(),
        ipv6: "fd00:96::3".to_string(),
        endpoints: vec!["203.0.113.10:41002".to_string()],
        handshake_secs: Some(12),
        path: Some("relay".to_string()),
        endpoint: None,
        relay_reason: Some("handshake_timeout".to_string()),
    })
    .expect("MapPeer 序列化")
}

/// 组装一份与 `status_value` 键序一致的订阅快照。
fn snapshot(status: &NodeStatus, extras: Value) -> Value {
    let mut value = serde_json::to_value(status).expect("NodeStatus 序列化");
    let map = value.as_object_mut().expect("对象");
    for (key, val) in extras.as_object().expect("对象") {
        map.insert(key.clone(), val.clone());
    }
    value
}

fn fixtures() -> Vec<(&'static str, Value)> {
    let identity = registered_info("mini", "100.96.0.1", Some(1_900_000_000));
    let mut fixtures = Vec::new();

    // 未注册：订阅快照在 hzd 侧补 desired_state。
    fixtures.push((
        "status-unregistered.json",
        snapshot(&NodeStatus::Unregistered, json!({"desired_state": "up"})),
    ));

    // 已注册、全直连。
    fixtures.push((
        "status-registered-direct.json",
        snapshot(
            &NodeStatus::Registered(identity.clone()),
            json!({
                "peers": [peer_direct("beefy-pc", 4)],
                "desired_state": "up",
                "dns_suffix": "hznet.internal",
                "coord_addr": "https://coord.example.com",
                "revoked": false,
                "version_hint": "",
                "diagnostics": {"route_repair": null, "dns_fallback": null},
                "policy": {"version": 0, "dropped": 0},
            }),
        ),
    ));

    // 已注册、部分中转：一个直连 + 一个因握手超时走中转（带原因）。
    fixtures.push((
        "status-registered-relay.json",
        snapshot(
            &NodeStatus::Registered(identity.clone()),
            json!({
                "peers": [
                    serde_json::to_value(peer_direct("beefy-pc", 4)).unwrap(),
                    peer_relay("cloud-vm"),
                ],
                "desired_state": "up",
                "dns_suffix": "hznet.internal",
                "coord_addr": "https://coord.example.com",
                "revoked": false,
                "version_hint": "behind",
                "diagnostics": {"route_repair": null, "dns_fallback": null},
                "policy": {"version": 0, "dropped": 0},
            }),
        ),
    ));

    // 已注册、与其他 VPN 工具冲突：路由被第三方网卡占用后自动修复的记录。
    fixtures.push((
        "status-registered-conflict.json",
        snapshot(
            &NodeStatus::Registered(identity.clone()),
            json!({
                "peers": [peer_direct("beefy-pc", 4)],
                "desired_state": "up",
                "dns_suffix": "hznet.internal",
                "coord_addr": "https://coord.example.com",
                "revoked": false,
                "version_hint": "",
                "diagnostics": {
                    "route_repair": {"at": 1_775_200_000, "cidr": "100.96.0.0/16", "previous": "taken_by:utun9"},
                    "dns_fallback": null,
                },
                "policy": {"version": 0, "dropped": 0},
            }),
        ),
    ));

    // 已吊销：审计行保留，无法通信（revoked 标记驱动 App「需要重新登录」态）。
    fixtures.push((
        "status-revoked.json",
        snapshot(
            &NodeStatus::Expired(identity.clone()),
            json!({
                "peers": [],
                "desired_state": "up",
                "dns_suffix": "hznet.internal",
                "coord_addr": "https://coord.example.com",
                "revoked": true,
                "version_hint": "",
                "diagnostics": {"route_repair": null, "dns_fallback": null},
                "policy": {"version": 0, "dropped": 0},
            }),
        ),
    ));

    // 已过期：身份仍在，重新登录恢复。
    fixtures.push((
        "status-expired.json",
        snapshot(
            &NodeStatus::Expired(identity.clone()),
            json!({
                "peers": [],
                "desired_state": "up",
                "dns_suffix": "hznet.internal",
                "coord_addr": "https://coord.example.com",
                "revoked": false,
                "version_hint": "",
                "diagnostics": {"route_repair": null, "dns_fallback": null},
                "policy": {"version": 0, "dropped": 0},
            }),
        ),
    ));

    // 有意断开（hz down）：身份保留，数据面停止。
    fixtures.push((
        "status-down.json",
        snapshot(
            &NodeStatus::Registered(identity.clone()),
            json!({
                "peers": [],
                "desired_state": "down",
                "dns_suffix": "hznet.internal",
                "coord_addr": "https://coord.example.com",
                "revoked": false,
                "version_hint": "",
                "diagnostics": {"route_repair": null, "dns_fallback": null},
                "policy": {"version": 0, "dropped": 0},
            }),
        ),
    ));

    // 登录轮询的进行中 / 完成形态（hzd IPC LoginProgress，serde tag=state）。
    fixtures.push(("login-pending.json", json!({"state": "pending"})));
    fixtures.push((
        "login-completed.json",
        json!({
            "state": "completed",
            "node": {
                "node_id": "n-mini",
                "name": "mini",
                "ipv4": "100.96.0.1",
                "ipv6": "fd00:96::1",
                "tags": [],
                "owner_user": "alice",
                "expires_at_unix": 1_900_000_000,
            },
        }),
    ));
    fixtures.push((
        "login-failed.json",
        json!({"state": "failed", "error": "登录等待超时，请重新执行 hz login"}),
    ));

    // diagnostics 响应：元数据 + status + netcheck 六项 + 版本 + 日志尾部（已脱敏）。
    fixtures.push((
        "diagnostics.json",
        json!({
            "schema_version": 1,
            "collected_at": "2026-10-29T10:00:01Z",
            "status": snapshot(
                &NodeStatus::Registered(identity.clone()),
                json!({
                    "peers": [peer_direct("beefy-pc", 4)],
                    "desired_state": "up",
                    "dns_suffix": "hznet.internal",
                    "coord_addr": "https://coord.example.com",
                    "revoked": false,
                    "version_hint": "",
                    "diagnostics": {"route_repair": null, "dns_fallback": null},
                    "policy": {"version": 0, "dropped": 0},
                }),
            ),
            "version": "0.4.0 (a1b2c3d)",
            "os": "macos",
            "arch": "aarch64",
            "netcheck": {
                "egress": {"physical": "en0", "default_route": "en0", "virtual_holds_default": false},
                "udp": {
                    "ipv4": {"ok": true, "stage": null, "error": null, "mapped": "203.0.113.9:41001"},
                    "ipv6": {"ok": false, "stage": "query", "error": "无该族 STUN 目标", "mapped": null},
                },
                "stun": {"targets": 2, "mapped": ["203.0.113.9:41001"], "nat": "easy"},
                "endpoints": [
                    {"addr": "192.168.31.63:51820", "kind": "lan", "suspicious": []},
                    {"addr": "203.0.113.9:41001", "kind": "stun", "suspicious": []},
                ],
                "ipv6_usable": false,
                "relay_rtt_ms": 12.5,
                "portmap": {"protocol": null, "external": null, "multi_nat": false},
                "peers": [
                    {"name": "beefy-pc", "node_id": "n-beefy-pc", "path": "direct", "punch": "success", "relay_reason": null},
                ],
            },
            "log_tail": [
                "2026-10-29T10:00:00Z INFO hzd starting",
                "2026-10-29T10:00:01Z INFO path=direct endpoint=203.0.113.9:41001 node_id=n-beefy-pc",
            ],
            "log_note": "最近 2 行（/Library/Logs/hzd.log，已脱敏）",
        }),
    ));

    fixtures
}

/// 重新生成全部 fixture（总是写入，代码里的定义是唯一事实源）；已提交的
/// 内容与新生成的不同时失败一次，提示把变化提交入库——CI 的
/// `git diff --exit-code clients/fixtures` 是同一件事的第二道闸。
#[test]
fn regenerate_contract_fixtures_and_flag_drift() {
    let dir = repo_root().join("clients/fixtures");
    std::fs::create_dir_all(&dir).expect("创建 clients/fixtures");
    let mut drifted: Vec<&str> = Vec::new();
    for (name, value) in fixtures() {
        let path = dir.join(name);
        let expected = serde_json::to_string_pretty(&value).expect("pretty 序列化");
        let committed = std::fs::read_to_string(&path).ok();
        let mut body = expected.clone();
        body.push('\n');
        std::fs::write(&path, body).unwrap_or_else(|error| panic!("写 {path:?} 失败：{error}"));
        if committed
            .as_deref()
            .is_some_and(|old| old.trim_end() != expected)
        {
            drifted.push(name);
        }
    }
    assert!(
        drifted.is_empty(),
        "fixture 定义与已提交内容不一致（已重写为最新，提交入库）：{drifted:?}"
    );
}
