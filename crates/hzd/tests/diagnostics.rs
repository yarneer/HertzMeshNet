//! Seam B（#84）：真实 hzd + 进程内 coord + 真实 UDS。diagnostics 返回字段
//! 齐全；向日志注入私钥 / Auth Key / 邀请码 / 登录 token 后，返回内容中均
//! 不出现，Node Name 与 Endpoint 仍在。独立测试二进制：HZD_LOG_FILE 只影响
//! 本进程。

use std::path::Path;
use std::time::Duration;

use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, serve};
use hz_coord::store::Store;
use hz_core::ipc::{self, Request, Response};
use hz_core::status::RegisteredInfo;

async fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("socket {} never appeared", path.display());
}

/// 注入用的敏感样本（形态与真实签发一致）。
const AUTH_KEY: &str = "hznet.c3VwZXJzZWNyZXRrZXlkb25vdGNoYXJlMTIz";
const INVITE: &str = "HZ-ABCD-EFGH";
const LOGIN_URL: &str = "https://coord.example.com/oidc/start/n-a1b2c3d4e5f6a7b8";
const PRIVATE_HEX: &str = "6d616368696e655f707269766174655f6b65795f6865785f3030313233343536";

#[tokio::test]
async fn diagnostics_returns_fields_and_redacts_secrets() {
    let coord_dir = tempfile::tempdir().unwrap();
    let store = Store::open(&coord_dir.path().join("coord.db"), AddressConfig::default())
        .await
        .unwrap();
    let auth_key = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, true, &[])
        .await
        .unwrap();
    let coord = serve(ServeConfig::new(
        store.clone(),
        "127.0.0.1:0".parse().unwrap(),
    ))
    .await
    .unwrap();
    let coord_addr = format!("http://{}", coord.local_addr);

    let node_dir = tempfile::tempdir().unwrap();
    let socket = node_dir.path().join("hzd.sock");

    // 日志文件：敏感行 + 有用行，外加超过 2000 行验证截尾。
    let log_path = node_dir.path().join("hzd.log");
    let mut log = String::new();
    for i in 0..2100 {
        log.push_str(&format!("noise line {i}\n"));
    }
    log.push_str(&format!("issued auth key {AUTH_KEY} to admin\n"));
    log.push_str(&format!("invite {INVITE} redeemed\n"));
    log.push_str(&format!("login_url={LOGIN_URL} expires soon\n"));
    log.push_str(&format!("machine key priv {PRIVATE_HEX} loaded\n"));
    log.push_str("node mini path=direct endpoint=203.0.113.9:41001 stun mapped\n");
    std::fs::write(&log_path, log).unwrap();
    // SAFETY: 本二进制只有这一个测试线程，daemon 尚未启动，无并发读写。
    unsafe { std::env::set_var("HZD_LOG_FILE", &log_path) };

    let daemon = tokio::spawn(hzd::run(node_dir.path().to_path_buf(), socket.clone()));
    wait_for_socket(&socket).await;
    let up = ipc::request(
        &socket,
        Request::new(
            1,
            "up",
            serde_json::json!({ "auth_key": auth_key, "coord_addr": coord_addr }),
        ),
    )
    .await
    .unwrap();
    let info: RegisteredInfo = match up {
        Response::Ok { result, .. } => serde_json::from_value(result).unwrap(),
        Response::Error { error, .. } => panic!("hz up 失败：{error}"),
    };

    let response = ipc::request(
        &socket,
        Request::new(2, "diagnostics", serde_json::json!({})),
    )
    .await
    .unwrap();
    let diagnostics = match response {
        Response::Ok { result, .. } => result,
        Response::Error { error, .. } => panic!("diagnostics 失败：{error}"),
    };

    // 字段齐全。
    assert!(diagnostics["status"]["peers"].is_array(), "{diagnostics}");
    assert!(diagnostics["status"]["desired_state"].is_string());
    assert!(
        diagnostics["netcheck"]["egress"].is_object(),
        "{diagnostics}"
    );
    assert_eq!(
        diagnostics["version"],
        hz_core::version::node_version(),
        "{diagnostics}"
    );
    assert_eq!(diagnostics["os"], std::env::consts::OS);
    assert_eq!(diagnostics["arch"], std::env::consts::ARCH);

    // log_tail：恰好最近 2000 行，说明里带路径与「已脱敏」。
    let tail = diagnostics["log_tail"].as_array().unwrap();
    assert_eq!(tail.len(), 2000, "日志共 2105 行，尾部应截到 2000");
    assert!(diagnostics["log_note"].as_str().unwrap().contains("已脱敏"));

    // 整份诊断（含 status/netcheck）中不得出现任何敏感样本。
    let whole = serde_json::to_string(&diagnostics).unwrap();
    assert!(!whole.contains(AUTH_KEY), "Auth Key 泄漏");
    assert!(!whole.contains(INVITE), "邀请码泄漏");
    assert!(!whole.contains("n-a1b2c3d4e5f6a7b8"), "登录 token 泄漏");
    assert!(!whole.contains(PRIVATE_HEX), "私钥 hex 泄漏");

    // Node Name 与 Endpoint 保留（status 的身份 + 日志里的排障信息）。
    assert!(whole.contains(&info.name), "Node Name 应保留");
    assert!(whole.contains("203.0.113.9:41001"), "Endpoint 应保留");
    let first_kept = tail[0].as_str().unwrap();
    assert!(
        first_kept.starts_with("noise line 105"),
        "尾部从第 105+1 行开始：{first_kept}"
    );

    daemon.abort();
    let _ = daemon.await;
    coord.shutdown();
}
