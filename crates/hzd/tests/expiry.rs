//! 到期反应（FR-3 / #11）：归属 User 的 Node 过期后，hzd 必须把会话翻到
//! Expired（`hz status` 显示「已过期」）、拆掉对端，并在本地保留全部身份材料。
//! 到期由 SQL 直写模拟（语义与真实跨越一致）；断言走 status IPC 的公共契约。

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

async fn status(socket: &Path) -> serde_json::Value {
    match ipc::request(socket, Request::new(2, "status", json!({})))
        .await
        .unwrap()
    {
        Response::Ok { result, .. } => result,
        Response::Error { error, .. } => panic!("status 出错：{error}"),
    }
}

#[tokio::test]
async fn daemon_marks_itself_expired_when_swept_out_of_the_map() {
    let store = Store::open_in_memory(AddressConfig::default())
        .await
        .unwrap();
    let mut config = ServeConfig::new(store.clone(), "127.0.0.1:0".parse().unwrap());
    config.map_sweep = Duration::from_millis(200);
    config.map_keepalive = Duration::from_secs(30);
    let handle = serve(config).await.unwrap();
    let coord_addr = format!("http://{}", handle.local_addr);
    let auth_key = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, false, &[])
        .await
        .unwrap();

    // 对端 Node 先在册，hzd 的 Map 里能看到它，证明订阅已建立。
    let other_dir = tempfile::tempdir().unwrap();
    register_with_auth_key(other_dir.path(), &auth_key, None, "node-b", &coord_addr)
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
    let registered = match response {
        Response::Ok { result, .. } => result,
        Response::Error { error, .. } => panic!("注册失败：{error}"),
    };
    let node_id = registered["node_id"].as_str().unwrap().to_string();
    let name = registered["name"].as_str().unwrap().to_string();
    let ipv4 = registered["ipv4"].as_str().unwrap().to_string();

    let mut saw_peer = false;
    for _ in 0..200 {
        let result = status(&socket).await;
        if result["registered"].as_bool() == Some(true)
            && result["peers"].as_array().is_some_and(|p| !p.is_empty())
        {
            saw_peer = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(saw_peer, "到期前 status 必须先处于已注册且能看到对端");

    // 到期：sweep 推来 removed=[自己]，hzd 应翻到 Expired。
    sqlx::query("UPDATE nodes SET expires_at_unix = ?1 WHERE id = ?2")
        .bind(hz_coord::store::unix_now() - 1)
        .bind(&node_id)
        .execute(store.pool())
        .await
        .unwrap();

    let mut expired = None;
    for _ in 0..300 {
        let result = status(&socket).await;
        if result["expired"].as_bool() == Some(true) {
            expired = Some(result);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    daemon.abort();
    let _ = daemon.await;
    handle.shutdown();
    handle.terminated().await;

    let expired = expired.expect("到期后 30 秒内 status 应翻到已过期");
    assert_eq!(expired["registered"].as_bool(), Some(false));
    assert_eq!(expired["node_id"].as_str(), Some(node_id.as_str()));
    assert_eq!(expired["name"].as_str(), Some(name.as_str()));
    assert_eq!(expired["ipv4"].as_str(), Some(ipv4.as_str()));
    assert_eq!(
        expired["peers"].as_array().map(Vec::len),
        Some(0),
        "过期后不得再展示可通信对端"
    );

    // 本地身份材料一件不少（ADR-0005：重新登录保身份）。
    for file in ["machine-key", "machine-key.pub", "node-key", "node-key.pub"] {
        assert!(
            dir.path().join(file).exists(),
            "过期不得删除 {}，重新登录要复用 Machine Key",
            file
        );
    }
    assert!(
        dir.path().join("registration.json").exists(),
        "注册身份必须保留在盘上"
    );
}

#[tokio::test]
async fn daemon_rejects_re_registration_via_auth_key_after_expiry() {
    let store = Store::open_in_memory(AddressConfig::default())
        .await
        .unwrap();
    let mut config = ServeConfig::new(store.clone(), "127.0.0.1:0".parse().unwrap());
    config.map_sweep = Duration::from_millis(200);
    config.map_keepalive = Duration::from_secs(30);
    let handle = serve(config).await.unwrap();
    let coord_addr = format!("http://{}", handle.local_addr);
    let auth_key = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, false, &[])
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
    let node_id = match response {
        Response::Ok { result, .. } => result["node_id"].as_str().unwrap().to_string(),
        Response::Error { error, .. } => panic!("注册失败：{error}"),
    };

    sqlx::query("UPDATE nodes SET expires_at_unix = ?1 WHERE id = ?2")
        .bind(hz_coord::store::unix_now() - 1)
        .bind(&node_id)
        .execute(store.pool())
        .await
        .unwrap();
    for _ in 0..300 {
        if status(&socket).await["expired"].as_bool() == Some(true) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let response = ipc::request(
        &socket,
        Request::new(
            3,
            "up",
            json!({"auth_key": auth_key, "coord_addr": coord_addr}),
        ),
    )
    .await
    .unwrap();
    daemon.abort();
    let _ = daemon.await;
    handle.shutdown();
    handle.terminated().await;

    match response {
        Response::Error { error, .. } => assert!(
            error.contains("已过期") && error.contains("重新登录"),
            "过期的 Node 再用 Auth Key 注册应被拒并指向重新登录，实际：{error}"
        ),
        Response::Ok { .. } => panic!("过期的 Node 不得经 Auth Key 续命"),
    }
}
