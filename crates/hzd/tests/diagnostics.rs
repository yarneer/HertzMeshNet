//! Seam B（#84 / #108 / #106）：真实 hzd + 进程内 coord + 真实 UDS。diagnostics
//! 返回字段齐全；向日志注入私钥 / Auth Key / 邀请码 / 登录 token / Bearer /
//! Cookie / JWT 后，返回内容中均不出现，Node Name 与 Endpoint 仍在。文件名里
//! 的密钥只出现在 `log_note`，用来卡住整包二次脱敏。journal 注入走
//! `HZD_JOURNAL_FILE`（与文件路径同一套脱敏 / 截断 / 预算）。独立测试二进制：
//! 这两个环境变量只影响本进程，测试之间用锁串行。

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
const LOGIN_URL_2: &str = "https://coord.example.com/oidc/start/n-0011223344556677";
const PRIVATE_HEX: &str = "6d616368696e655f707269766174655f6b65795f6865785f3030313233343536";
const BEARER: &str = "sk_live_51Habcdefghijklmnopqrstuv";
const BEARER_2: &str = "sk_live_51Hzzzzzzzzzzzzzzzzzzzz";
const COOKIE: &str = "s3cr3tc00k13value";
const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
/// 只放进日志文件名（进 `log_note`，不进 log_tail），整包二次 redact 才能剥掉。
const NOTE_LEAK: &str = "hznet.bm90ZWxla2tleWRvbm90c2hhcmUxMjM0NTY";

/// 文件路径与 journal 路径都写进程环境变量；cargo 默认并行跑这两个测试。
static LOG_ENV: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn diagnostics_returns_fields_and_redacts_secrets() {
    let _env = LOG_ENV.lock().await;
    unsafe { std::env::remove_var("HZD_JOURNAL_FILE") };
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
    let log_path = node_dir.path().join(format!("{NOTE_LEAK}.log"));
    let mut log = String::new();
    for i in 0..2100 {
        log.push_str(&format!("noise line {i}\n"));
    }
    log.push_str(&format!(
        "issued auth key {AUTH_KEY} to admin {LOGIN_URL} {LOGIN_URL_2}\n"
    ));
    log.push_str(&format!(
        "invite {INVITE} redeemed Bearer {BEARER} bearer {BEARER_2}\n"
    ));
    log.push_str(&format!("login_url={LOGIN_URL} expires soon\n"));
    log.push_str(&format!(
        "machine key priv {PRIVATE_HEX} loaded Authorization: Basic dXNlcjpwYXNzdzByZA==\n"
    ));
    log.push_str(&format!(
        "node mini path=direct endpoint=203.0.113.9:41001 Cookie: hz_admin={COOKIE} id_token={JWT}\n"
    ));
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
    assert_eq!(diagnostics["schema_version"].as_i64(), Some(1));
    let collected_at = diagnostics["collected_at"].as_str().expect("collected_at");
    assert!(collected_at.ends_with('Z'), "{collected_at}");
    let parsed = chrono::DateTime::parse_from_rfc3339(collected_at)
        .unwrap_or_else(|error| panic!("{collected_at}: {error}"));
    let skew = (chrono::Utc::now() - parsed.with_timezone(&chrono::Utc))
        .num_seconds()
        .abs();
    assert!(skew < 120, "{collected_at}");

    // log_tail：恰好最近 2000 行，说明里带路径与「已脱敏」。
    let tail = diagnostics["log_tail"].as_array().unwrap();
    assert_eq!(tail.len(), 2000, "日志共 2105 行，尾部应截到 2000");
    assert!(diagnostics["log_note"].as_str().unwrap().contains("已脱敏"));

    // 整份诊断（含 status/netcheck）中不得出现任何敏感样本。
    let whole = serde_json::to_string(&diagnostics).unwrap();
    assert!(!whole.contains(AUTH_KEY), "Auth Key 泄漏");
    assert!(
        !whole.contains("bm90ZWxla2tleWRvbm90c2hhcmU"),
        "log_note 路径泄漏"
    );
    assert!(!whole.contains(INVITE), "邀请码泄漏");
    assert!(!whole.contains("n-a1b2c3d4e5f6a7b8"), "登录 token 泄漏");
    assert!(
        !whole.contains("n-0011223344556677"),
        "第二处登录 token 泄漏"
    );
    assert!(!whole.contains(PRIVATE_HEX), "私钥 hex 泄漏");
    assert!(!whole.contains(BEARER), "Bearer 泄漏");
    assert!(!whole.contains(BEARER_2), "第二处 Bearer 泄漏");
    assert!(!whole.contains(COOKIE), "cookie 泄漏");
    assert!(
        !whole.contains("dXNlcjpwYXNzdzByZA=="),
        "Authorization 泄漏"
    );
    assert!(
        !whole.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        "JWT 泄漏"
    );

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

#[tokio::test]
async fn journal_diagnostics_redacts_long_lines_and_stays_under_ipc() {
    let pem_body = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA";
    let mut raw = String::new();
    for i in 0..80 {
        raw.push_str(&format!("old-{i:03} {}\n", "o".repeat(7000)));
    }
    raw.push_str("-----BEGIN PRIVATE KEY-----\n");
    raw.push_str(pem_body);
    raw.push('\n');
    raw.push_str("morebase64bodyline==\n");
    raw.push_str("-----END PRIVATE KEY-----\n");
    raw.push_str(&format!(
        "journal-long {PRIVATE_HEX} {}\n",
        "L".repeat(9 * 1024)
    ));
    raw.push_str("journal-newest endpoint=203.0.113.9:41001\n");

    let node_dir = tempfile::tempdir().unwrap();
    let journal = node_dir.path().join("journal.log");
    std::fs::write(&journal, raw).unwrap();
    let socket = node_dir.path().join("hzd.sock");

    let _env = LOG_ENV.lock().await;
    unsafe {
        std::env::remove_var("HZD_LOG_FILE");
        std::env::set_var("HZD_JOURNAL_FILE", &journal);
    }

    let daemon = tokio::spawn(hzd::run(node_dir.path().to_path_buf(), socket.clone()));
    wait_for_socket(&socket).await;
    let response = ipc::request(
        &socket,
        Request::new(1, "diagnostics", serde_json::json!({})),
    )
    .await
    .unwrap();
    let diagnostics = match response {
        Response::Ok { result, .. } => result,
        Response::Error { error, .. } => panic!("diagnostics 失败：{error}"),
    };

    let tail = diagnostics["log_tail"].as_array().unwrap();
    let whole = serde_json::to_string(&diagnostics).unwrap();
    assert!(!whole.contains(pem_body), "跨行 PEM 泄漏");
    assert!(!whole.contains("morebase64"), "PEM 体泄漏");
    assert!(!whole.contains("BEGIN PRIVATE KEY"), "PEM 头泄漏");
    assert!(!whole.contains(PRIVATE_HEX), "超长行私钥泄漏");
    assert!(
        tail.iter()
            .any(|line| line.as_str().unwrap().ends_with("…(截断)")),
        "超长行应截断：{tail:?}"
    );
    assert!(
        !whole.contains("old-000"),
        "预算应丢掉最老行，且 IPC 仍成功"
    );
    assert!(whole.contains("journal-newest"), "{whole}");
    assert!(whole.contains("203.0.113.9:41001"), "{whole}");
    let note = diagnostics["log_note"].as_str().unwrap();
    assert!(
        note.contains("已脱敏") && note.contains("journal"),
        "{note}"
    );
    assert!(note.contains(&format!("最近 {} 行", tail.len())), "{note}");

    unsafe { std::env::remove_var("HZD_JOURNAL_FILE") };
    daemon.abort();
    let _ = daemon.await;
}
