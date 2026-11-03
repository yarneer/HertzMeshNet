//! #97 Seam B（hzd 层）：coord 配置了 `--public-relay-addr` 时，注册响应的
//! Relay 地址进入 Node 的注册身份（registration.json / `hz status`）——
//! 只填 coord 地址的节点（Android App、macOS #91）也能找到 Relay 与 STUN。

use std::path::Path;
use std::time::Duration;

use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, serve};
use hz_coord::store::Store;
use hz_core::ipc::{self, Request, Response};
use hz_engine::EngineConfig;

async fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("socket {} never appeared", path.display());
}

#[tokio::test]
async fn coord_provided_relay_lands_in_registration_and_status() {
    let coord_dir = tempfile::tempdir().unwrap();
    let store = Store::open(&coord_dir.path().join("coord.db"), AddressConfig::default())
        .await
        .unwrap();
    let auth_key = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, true, &[])
        .await
        .unwrap();
    let mut config = ServeConfig::new(store, "127.0.0.1:0".parse().unwrap());
    config.public_relay_addr = Some("https://relay.example.com".to_string());
    config.public_stun_addrs = vec!["relay.example.com:3478".to_string()];
    let coord = serve(config).await.unwrap();
    let coord_addr = format!("http://{}", coord.local_addr);

    let node_dir = tempfile::tempdir().unwrap();
    let socket = node_dir.path().join("hzd.sock");
    // 引擎不配显式 Relay（模拟只填 coord 地址的 Client App 节点）。
    let daemon = tokio::spawn(hzd::run_with(
        EngineConfig::default(),
        node_dir.path().to_path_buf(),
        socket.clone(),
    ));
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
    match up {
        Response::Ok { result, .. } => {
            assert_eq!(
                result["relay_addr"].as_str(),
                Some("https://relay.example.com"),
                "coord 下发的 Relay 地址应随注册身份返回"
            );
            assert_eq!(
                result["stun_addrs"][0].as_str(),
                Some("relay.example.com:3478")
            );
        }
        Response::Error { error, .. } => panic!("up 失败：{error}"),
    }

    let status = ipc::request(&socket, Request::new(2, "status", serde_json::json!({})))
        .await
        .unwrap();
    match status {
        Response::Ok { result, .. } => {
            assert_eq!(
                result["relay_addr"].as_str(),
                Some("https://relay.example.com")
            );
        }
        Response::Error { error, .. } => panic!("status 失败：{error}"),
    }
    daemon.abort();
    let _ = daemon.await;
    coord.shutdown();
    coord.terminated().await;
}
