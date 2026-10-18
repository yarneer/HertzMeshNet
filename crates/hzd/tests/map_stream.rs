//! FR-6 宕机容忍的端到端链路（真实 tonic over loopback + 内存 SQLite + 真实 hzd）：
//! Coordination Server 停止后缓存仍可查、hzd 重启后凭 network-map.json 恢复对端视图，
//! 服务恢复后未重启的 hzd 自动重连并看到后注册的 Node。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, ServeHandle, serve};
use hz_coord::store::Store;
use hz_core::coord_client::register_with_auth_key;
use hz_core::ipc::{self, Request, Response};
use serde_json::json;

async fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("socket {} never appeared", path.display());
}

async fn status_peers(socket: &Path) -> Vec<serde_json::Value> {
    let response = ipc::request(socket, Request::new(1, "status", json!({})))
        .await
        .expect("hzd status 应答");
    match response {
        Response::Ok { result, .. } => result
            .get("peers")
            .and_then(|p| p.as_array())
            .cloned()
            .unwrap_or_default(),
        Response::Error { error, .. } => panic!("status 出错：{error}"),
    }
}

fn peer_ipv4s(peers: &[serde_json::Value]) -> HashSet<String> {
    peers
        .iter()
        .map(|p| p["ipv4"].as_str().unwrap_or_default().to_string())
        .collect()
}

async fn up(socket: &Path, auth_key: &str, coord_addr: &str) -> serde_json::Value {
    let response = ipc::request(
        socket,
        Request::new(
            2,
            "up",
            json!({"auth_key": auth_key, "coord_addr": coord_addr}),
        ),
    )
    .await
    .unwrap();
    match response {
        Response::Ok { result, .. } => result,
        Response::Error { error, .. } => panic!("up 失败：{error}"),
    }
}

async fn restart_on_same_addr(store: &Store, addr: std::net::SocketAddr) -> ServeHandle {
    for _ in 0..100 {
        let mut config = ServeConfig::new(store.clone(), "127.0.0.1:0".parse().unwrap());
        config.listen = addr;
        if let Ok(handle) = serve(config).await {
            return handle;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("无法在 {addr} 上重启 coord serve");
}

#[tokio::test]
async fn daemon_survives_coord_outage_and_reconnects_after_recovery() {
    // coord 侧的存储错误只走 tracing；不装 subscriber 时测试只剩 tonic 状态码，
    // 无法定位是哪条 SQL 失败。
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
    let store = Store::open_in_memory(AddressConfig::default())
        .await
        .unwrap();
    let handle = serve(ServeConfig::new(
        store.clone(),
        "127.0.0.1:0".parse().unwrap(),
    ))
    .await
    .unwrap();
    let coord_addr = format!("http://{}", handle.local_addr);
    let key_a = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, true, &[])
        .await
        .unwrap();
    let key_b = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, true, &[])
        .await
        .unwrap();
    let key_c = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, true, &[])
        .await
        .unwrap();

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let sock_a = dir_a.path().join("hzd.sock");
    let sock_b = dir_b.path().join("hzd.sock");
    let daemon_a = tokio::spawn(hzd::run(dir_a.path().to_path_buf(), sock_a.clone()));
    let daemon_b = tokio::spawn(hzd::run(dir_b.path().to_path_buf(), sock_b.clone()));
    wait_for_socket(&sock_a).await;
    wait_for_socket(&sock_b).await;

    let info_a = up(&sock_a, &key_a, &coord_addr).await;
    let info_b = up(&sock_b, &key_b, &coord_addr).await;
    let ipv4_a = info_a["ipv4"].as_str().unwrap().to_string();
    let ipv4_b = info_b["ipv4"].as_str().unwrap().to_string();

    let wait_peer = |socket: PathBuf, expected: String| async move {
        for _ in 0..200 {
            if peer_ipv4s(&status_peers(&socket).await).contains(&expected) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("20 秒内未在对端 status 里看到 {expected}");
    };
    wait_peer(sock_a.clone(), ipv4_b.clone()).await;
    wait_peer(sock_b.clone(), ipv4_a.clone()).await;

    // 模拟 Coordination Server 宕机：两条流都会断，缓存必须仍然可查。
    let coord_local = handle.local_addr;
    handle.shutdown();
    handle.terminated().await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        peer_ipv4s(&status_peers(&sock_a).await).contains(&ipv4_b),
        "coord 停机后 A 的 status 仍应从缓存列出 B"
    );
    assert!(
        peer_ipv4s(&status_peers(&sock_b).await).contains(&ipv4_a),
        "coord 停机后 B 的 status 仍应从缓存列出 A"
    );

    // coord 仍不可达时重启 A（模拟整机重启）：对端视图从 network-map.json 恢复。
    daemon_a.abort();
    let _ = daemon_a.await;
    let daemon_a = tokio::spawn(hzd::run(dir_a.path().to_path_buf(), sock_a.clone()));
    wait_for_socket(&sock_a).await;
    let mut restored = false;
    for _ in 0..100 {
        if peer_ipv4s(&status_peers(&sock_a).await).contains(&ipv4_b) {
            restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(restored, "hzd 重启后应凭缓存恢复对端视图（coord 不可达）");

    // 服务恢复：未重启的 hzd 自动重连；之后注册的 Node 必须不重启就对两端可见。
    let handle = restart_on_same_addr(&store, coord_local).await;
    let dir_c = tempfile::tempdir().unwrap();
    let info_c = register_with_auth_key(dir_c.path(), &key_c, "node-c", &coord_addr)
        .await
        .unwrap();
    let ipv4_c = info_c.ipv4.clone();

    // 每端各自应看到的对端集合（自己被排除在外）。
    for (socket, expected, label) in [
        (
            &sock_a,
            HashSet::from([ipv4_b.clone(), ipv4_c.clone()]),
            "A（重启过）",
        ),
        (
            &sock_b,
            HashSet::from([ipv4_a.clone(), ipv4_c.clone()]),
            "B（未重启）",
        ),
    ] {
        let mut seen = HashSet::new();
        for _ in 0..600 {
            seen = peer_ipv4s(&status_peers(socket).await);
            if seen == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            seen, expected,
            "{label} 应在 60 秒内自动重连并看到 node-c 与原有对端"
        );
        let peers = status_peers(socket).await;
        let node_c = peers
            .iter()
            .find(|p| p["ipv4"].as_str() == Some(ipv4_c.as_str()))
            .unwrap();
        assert_eq!(node_c["name"].as_str().unwrap(), "node-c");
    }

    daemon_a.abort();
    let _ = daemon_a.await;
    daemon_b.abort();
    let _ = daemon_b.await;
    handle.shutdown();
    handle.terminated().await;
}
