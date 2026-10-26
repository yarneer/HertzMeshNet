//! 已注册 hzd 的数据面装配：`up` 之后自动订阅 Network Map 并在 status 中展示对端。
//! TUN 转发只在 Linux 生效；本测试覆盖注册 → 订阅 → 对端可见的完整链路（无 TUN 平台
//! 上 hzd 降级为纯控制面，Map 装配依然必须工作）。

use std::path::Path;
use std::time::Duration;

use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, serve};
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

#[tokio::test]
async fn daemon_subscribes_to_map_and_lists_peers_after_up() {
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
    let auth_key = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, false, &[])
        .await
        .unwrap();

    // 先注册第二个 Node，hzd 的 Network Map 里就应当能看到它。
    let other_dir = tempfile::tempdir().unwrap();
    let other = register_with_auth_key(other_dir.path(), &auth_key, None, "node-b", &coord_addr)
        .await
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let daemon = tokio::spawn(hzd::run(dir.path().to_path_buf(), socket.clone()));
    wait_for_socket(&socket).await;

    let response = ipc::request(
        &socket,
        Request::new(
            1,
            "up",
            json!({"auth_key": auth_key, "coord_addr": coord_addr}),
        ),
    )
    .await
    .unwrap();
    assert!(
        matches!(response, Response::Ok { .. }),
        "注册应成功：{response:?}"
    );

    let mut status = None;
    for _ in 0..200 {
        let response = ipc::request(&socket, Request::new(2, "status", json!({})))
            .await
            .unwrap();
        if let Response::Ok { result, .. } = response {
            if result
                .get("peers")
                .is_some_and(|p| !p.as_array().unwrap().is_empty())
            {
                status = Some(result);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    daemon.abort();
    let _ = daemon.await;
    handle.shutdown();
    handle.terminated().await;

    let status = status.expect("注册后 20 秒内 status 应列出 Network Map 中的对端");
    let peers = status["peers"].as_array().unwrap();
    assert_eq!(peers.len(), 1, "Map 只有一个对端（自身被排除）：{peers:?}");
    let peer = &peers[0];
    assert_eq!(peer["name"].as_str().unwrap(), other.name);
    assert_eq!(peer["ipv4"].as_str().unwrap(), other.ipv4);
    assert_eq!(peer["ipv6"].as_str().unwrap(), other.ipv6);
    // 未握手是合法状态（对端没有数据面在线），但字段必须在。
    assert!(peer.get("handshake_secs").is_some());
}
