use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hz_core::ipc::{self, Request, Response};
use hz_core::status::NodeStatus;
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
async fn status_request_returns_unregistered_payload() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let server = tokio::spawn({
        let socket = socket.clone();
        async move {
            ipc::serve(
                &socket,
                Arc::new(|request: ipc::Request| {
                    assert_eq!(request.method, "status");
                    serde_json::to_value(NodeStatus::Unregistered).map_err(|e| e.to_string())
                }),
            )
            .await
        }
    });
    wait_for_socket(&socket).await;

    let response = ipc::request(&socket, Request::new(1, "status", json!({})))
        .await
        .unwrap();
    server.abort();

    match response {
        Response::Ok { id, result } => {
            assert_eq!(id, 1);
            assert_eq!(result, json!({"registered": false}));
        }
        Response::Error { error, .. } => panic!("unexpected error response: {error}"),
    }
}
