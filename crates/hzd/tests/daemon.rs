use std::path::Path;
use std::time::Duration;

use hz_core::ipc::{self, Request, Response};
use serde_json::json;

async fn wait_for_socket(path: &Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("socket {} never appeared", path.display());
}

#[tokio::test]
async fn daemon_answers_status_and_keeps_keys_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().to_path_buf();
    let socket = dir.path().join("hzd.sock");

    let daemon = tokio::spawn(hzd::run(state_dir.clone(), socket.clone()));
    wait_for_socket(&socket).await;
    let response = ipc::request(&socket, Request::new(1, "status", json!({})))
        .await
        .unwrap();
    daemon.abort();
    let _ = daemon.await;

    match response {
        Response::Ok { result, .. } => assert_eq!(result, json!({"registered": false})),
        Response::Error { error, .. } => panic!("unexpected error response: {error}"),
    }

    let machine_key_before = std::fs::read(dir.path().join("machine-key")).unwrap();
    let node_key_before = std::fs::read(dir.path().join("node-key")).unwrap();

    let daemon = tokio::spawn(hzd::run(state_dir, socket.clone()));
    wait_for_socket(&socket).await;
    let response = ipc::request(&socket, Request::new(2, "status", json!({})))
        .await
        .unwrap();
    daemon.abort();
    let _ = daemon.await;

    assert!(matches!(response, Response::Ok { .. }));
    assert_eq!(
        std::fs::read(dir.path().join("machine-key")).unwrap(),
        machine_key_before,
        "hzd 重启不得改写 Machine Key 文件"
    );
    assert_eq!(
        std::fs::read(dir.path().join("node-key")).unwrap(),
        node_key_before,
        "hzd 重启不得改写 Node Key 文件"
    );
}
