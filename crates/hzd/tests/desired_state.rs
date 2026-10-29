//! Seam B（#81）：真实 hzd + 进程内 coord + 真实 UDS。
//! down 后 Network Map 流断开、status 为 down；重启 hzd 仍为 down 且不启动
//! 数据面；up 后恢复，重启后自动连接。

use std::path::Path;
use std::time::Duration;

use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, serve};
use hz_coord::store::Store;
use hz_core::ipc::{self, Request, Response};
use hz_core::status::{NodeStatus, RegisteredInfo};
use serde_json::Value;

async fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("socket {} never appeared", path.display());
}

async fn ipc_json(socket: &Path, id: u64, method: &str, params: Value) -> Result<Value, String> {
    match ipc::request(socket, Request::new(id, method, params))
        .await
        .unwrap()
    {
        Response::Ok { result, .. } => Ok(result),
        Response::Error { error, .. } => Err(error),
    }
}

async fn status(socket: &Path) -> Value {
    let mut last = String::new();
    for _ in 0..100 {
        match ipc_json(socket, 1, "status", serde_json::json!({})).await {
            Ok(value) => return value,
            Err(error) => last = error,
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("status 一直失败：{last}");
}

async fn wait_online(coord: &hz_coord::service::ServeHandle, node_id: &str, expect: bool) {
    for _ in 0..200 {
        if coord.hub.is_online(node_id) == expect {
            return;
        }
        // hub 要等下一次投递才发现断线：注册一个无关 Node 触发存储变更。
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("node {node_id} 在线态未变为 {expect}");
}

#[tokio::test]
async fn down_persists_across_restart_and_up_restores() {
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
    let state_dir = node_dir.path().to_path_buf();
    let socket = node_dir.path().join("hzd.sock");

    let daemon = tokio::spawn(hzd::run(state_dir.clone(), socket.clone()));
    wait_for_socket(&socket).await;

    // 注册（带 Auth Key）→ desired_state=up、coord 侧在线。
    let info_v = ipc_json(
        &socket,
        1,
        "up",
        serde_json::json!({ "auth_key": auth_key, "coord_addr": coord_addr }),
    )
    .await
    .unwrap();
    let info: RegisteredInfo = serde_json::from_value(info_v).unwrap();
    assert_eq!(status(&socket).await["desired_state"], "up");
    wait_online(&coord, &info.node_id, true).await;
    // 触发 hub 变更探测的帮手：注册另一个 Node（走 store 直写）。
    let poke = store
        .register_node(&[9u8; 32], &[9u8; 32], "bystander", &[], None, None)
        .await
        .unwrap();
    let _ = poke;

    // ---- down ----
    let down = ipc_json(&socket, 2, "down", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(down["desired_state"], "down");
    assert_eq!(status(&socket).await["desired_state"], "down");
    // Network Map 流断开：hub 在下一次投递时移除登记（用 store 变更触发）。
    store
        .register_node(&[8u8; 32], &[8u8; 32], "bystander2", &[], None, None)
        .await
        .unwrap();
    wait_online(&coord, &info.node_id, false).await;
    // status 仍能给出身份（保留注册）。
    let status_value = status(&socket).await;
    let parsed: NodeStatus = serde_json::from_value(status_value.clone()).unwrap();
    assert!(
        matches!(parsed, NodeStatus::Registered(_)),
        "{status_value}"
    );

    // ---- 重启 hzd：仍为 down、不启动数据面 ----
    daemon.abort();
    let _ = daemon.await;
    // socket 文件随 serve 退出清理；旧 inode 作废，等新 socket 出现。
    let daemon = tokio::spawn(hzd::run(state_dir.clone(), socket.clone()));
    wait_for_socket(&socket).await;
    let status_value = status(&socket).await;
    assert_eq!(status_value["desired_state"], "down", "{status_value}");
    // 未启动数据面：hub 不该出现该 Node（给足时间 + 触发探测）。
    store
        .register_node(&[7u8; 32], &[7u8; 32], "bystander3", &[], None, None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !coord.hub.is_online(&info.node_id),
        "down 状态重启后不应自动连上 Network Map"
    );

    // ---- up（已注册，不带任何 key）：恢复数据面、不重新注册 ----
    let up_again = ipc_json(&socket, 3, "up", serde_json::json!({}))
        .await
        .unwrap();
    let again: RegisteredInfo = serde_json::from_value(up_again).unwrap();
    assert_eq!(again.node_id, info.node_id, "up 不重新注册，身份不变");
    assert_eq!(again.name, info.name);
    assert_eq!(again.ipv4, info.ipv4);
    assert_eq!(status(&socket).await["desired_state"], "up");
    store
        .register_node(&[6u8; 32], &[6u8; 32], "bystander4", &[], None, None)
        .await
        .unwrap();
    wait_online(&coord, &info.node_id, true).await;

    // ---- 重启后自动连接（desired_state=up）----
    daemon.abort();
    let _ = daemon.await;
    let daemon = tokio::spawn(hzd::run(state_dir.clone(), socket.clone()));
    wait_for_socket(&socket).await;
    assert_eq!(status(&socket).await["desired_state"], "up");
    store
        .register_node(&[5u8; 32], &[5u8; 32], "bystander5", &[], None, None)
        .await
        .unwrap();
    wait_online(&coord, &info.node_id, true).await;

    daemon.abort();
    let _ = daemon.await;
    coord.shutdown();
}
