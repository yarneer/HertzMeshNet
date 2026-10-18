use std::path::Path;
use std::time::Duration;

use hz_core::ipc::{self, Request, Response, handler};
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
                handler(|request: ipc::Request| async move {
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

#[tokio::test]
async fn oversized_line_is_rejected_instead_of_buffered() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let server = tokio::spawn({
        let socket = socket.clone();
        async move {
            ipc::serve(
                &socket,
                handler(|_request: ipc::Request| async { Ok(json!({})) }),
            )
            .await
        }
    });
    wait_for_socket(&socket).await;

    let stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
    use tokio::io::AsyncWriteExt;
    let (mut reader, mut writer) = stream.into_split();
    // 2 MiB 无换行输入：必须在 1 MiB 上限处报错断开，而不是继续吞内存。
    // 服务端断开后写端可能拿到 broken pipe，属预期。
    let _ = writer.write_all(&vec![b'a'; 2 * 1024 * 1024]).await;

    let mut response = String::new();
    use tokio::io::AsyncReadExt;
    let mut raw = Vec::new();
    // 对端因超限断开后，Linux 会给未排干的连接回 ECONNRESET 而非 EOF，
    // 收下断开前已到达的字节即可，读错误本身也是预期行为。
    loop {
        let mut buf = [0u8; 8192];
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    }
    server.abort();
    response.push_str(&String::from_utf8_lossy(&raw));
    assert!(
        !response.contains("\"result\""),
        "超限请求不应得到正常响应，实际：{response}"
    );
}
