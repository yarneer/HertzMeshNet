//! Seam B（hzd 层）：真实 hzd + 真实 coord（临时库、临时端口、真实 UDS），
//! `up` 完成注册，重启 hzd 后状态仍从 registration.json 恢复为 Registered。

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use hz_coord::addr::AddressConfig;
use hz_coord::name::NodeName;
use hz_coord::service::{ServeConfig, serve};
use hz_coord::store::Store;
use hz_core::coord_client::local_hostname;
use hz_core::ipc::{self, Request, Response};
use hz_core::status::{NodeStatus, RegisteredInfo};

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
async fn hz_up_registers_and_survives_restart() {
    let coord_dir = tempfile::tempdir().unwrap();
    let store = Store::open(&coord_dir.path().join("coord.db"), AddressConfig::default())
        .await
        .unwrap();
    let auth_key = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, true, &[])
        .await
        .unwrap();
    let coord = serve(ServeConfig::new(
        store.pool().clone(),
        "127.0.0.1:0".parse().unwrap(),
    ))
    .await
    .unwrap();
    let coord_addr = format!("http://{}", coord.local_addr);

    let node_dir = tempfile::tempdir().unwrap();
    let state_dir = node_dir.path().to_path_buf();
    let socket = node_dir.path().join("hzd.sock");

    let daemon = tokio::spawn(hzd::run(state_dir.clone(), socket.clone()));
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
    let granted = match up {
        Response::Ok { result, .. } => serde_json::from_value::<RegisteredInfo>(result).unwrap(),
        Response::Error { error, .. } => panic!("hz up 失败：{error}"),
    };

    let expected_name = NodeName::normalize(&local_hostname());
    assert_eq!(
        granted.name, expected_name,
        "Node Name 应取规范化后的主机名"
    );
    let ipv4: std::net::Ipv4Addr = granted.ipv4.parse().unwrap();
    assert!(AddressConfig::default().cidr.contains(ipv4));
    assert!(ipv4 != std::net::Ipv4Addr::new(100, 96, 0, 53));

    let status = ipc::request(&socket, Request::new(2, "status", serde_json::json!({})))
        .await
        .unwrap();
    match status {
        Response::Ok { result, .. } => {
            let parsed: NodeStatus = serde_json::from_value(result).unwrap();
            assert_eq!(
                parsed,
                NodeStatus::Registered(granted.clone()),
                "注册后 status 应返回授予的身份"
            );
        }
        Response::Error { error, .. } => panic!("status 失败：{error}"),
    }

    let registration_path = state_dir.join("registration.json");
    let mode = std::fs::metadata(&registration_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "registration.json 权限必须是 0600");

    daemon.abort();
    let _ = daemon.await;
    coord.shutdown();
    coord.terminated().await;

    let daemon = tokio::spawn(hzd::run(state_dir, socket.clone()));
    wait_for_socket(&socket).await;
    let status = ipc::request(&socket, Request::new(3, "status", serde_json::json!({})))
        .await
        .unwrap();
    daemon.abort();
    let _ = daemon.await;

    match status {
        Response::Ok { result, .. } => {
            let parsed: NodeStatus = serde_json::from_value(result).unwrap();
            assert_eq!(
                parsed,
                NodeStatus::Registered(granted),
                "重启后应从 registration.json 恢复注册状态"
            );
        }
        Response::Error { error, .. } => panic!("重启后 status 失败：{error}"),
    }
}
