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

// #26：hzd 以 root 运行时，普通用户也要能连上 socket 做只读查询；
// 是否允许具体请求由按调用方 uid 的授权决定，而不是靠文件权限一刀切。
#[tokio::test]
async fn socket_is_connectable_by_any_local_user() {
    use std::os::unix::fs::PermissionsExt;

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
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    server.abort();

    assert_eq!(mode, 0o666, "socket 权限应为 0666，实际 {mode:o}");
}

// #26：socket 对所有本机用户开放后，越权由按调用方 uid 的授权兜住：
// 只读查询任何人可做；注册、Policy、Auth Key、Node 管理等只允许 root 或 hzd 同一用户。
#[test]
fn read_only_methods_are_open_to_any_local_user() {
    let (hzd_uid, someone) = (0, 501);
    assert!(ipc::authorize("status", someone, hzd_uid).is_ok());
    assert!(ipc::authorize("ping", someone, hzd_uid).is_ok());
    assert!(ipc::authorize("netcheck", someone, hzd_uid).is_ok());
}

#[test]
fn state_changing_methods_need_root_or_the_daemon_user() {
    let (hzd_uid, someone) = (0, 501);
    for method in [
        "up",
        "login_poll",
        "policy_push",
        "policy_get",
        "policy_rollback",
        "authkey_create",
        "authkey_revoke",
        "node_list",
        "node_rename",
        "node_delete",
        "node_revoke",
    ] {
        let error = ipc::authorize(method, someone, hzd_uid).expect_err(method);
        assert!(
            error.contains("sudo"),
            "{method} 的拒绝提示应引导用 sudo：{error}"
        );
        assert!(
            ipc::authorize(method, 0, hzd_uid).is_ok(),
            "root 可执行 {method}"
        );
    }
    // 开发/测试场景 hzd 以普通用户运行：同一用户可执行全部操作。
    assert!(ipc::authorize("authkey_create", 501, 501).is_ok());
}

// ---------------------------------------------------------------------------
// #95：一请求多响应。以下用测试专用的流式方法覆盖验收项。
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc as StdArc;

use hz_core::ipc::{serve_with, stream_handler};

/// 启动带流式方法的服务：普通方法恒回 `{"single":true}`；
/// `test.stream` 按传入闭包的行为推送。
async fn serve_streaming<F, Fut>(socket: &Path, stream: F) -> StreamsProbe
where
    F: Fn(ipc::Request, tokio::sync::mpsc::Sender<Response>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let mut streams = HashMap::new();
    streams.insert("test.stream".to_string(), stream_handler(stream));
    let socket = socket.to_path_buf();
    let server = tokio::spawn(async move {
        let _ = serve_with(
            &socket,
            handler(|_request: ipc::Request| async { Ok(json!({"single": true})) }),
            Arc::new(streams),
        )
        .await;
    });
    StreamsProbe { server }
}

struct StreamsProbe {
    server: tokio::task::JoinHandle<()>,
}

impl StreamsProbe {
    async fn stop(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

/// 流式方法对同一请求 id 逐行推送多条响应，流结束后连接收尾（通道关闭）。
#[tokio::test]
async fn streaming_method_pushes_multiple_lines_until_finished() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let probe = serve_streaming(&socket, |request, sender| async move {
        for step in 1..=3 {
            let _ = sender
                .send(Response::Ok {
                    id: request.id,
                    result: json!({ "step": step }),
                })
                .await;
        }
    })
    .await;
    wait_for_socket(&socket).await;

    let mut rx = ipc::request_stream(&socket, Request::new(7, "test.stream", json!({})))
        .await
        .unwrap();
    let mut steps = Vec::new();
    while let Some(response) = rx.recv().await {
        match response {
            Response::Ok { id, result } => {
                assert_eq!(id, 7, "每行都携带同一请求 id");
                steps.push(result["step"].as_u64().unwrap());
            }
            Response::Error { error, .. } => panic!("unexpected error: {error}"),
        }
    }
    probe.stop().await;
    assert_eq!(steps, vec![1, 2, 3]);
    // 流结束后通道关闭（recv 已返回 None 才能走到这里）。
}

/// 客户端断开时服务端停止推送并释放资源，同一 hzd 的其他连接不受影响。
#[tokio::test]
async fn client_disconnect_stops_the_stream_and_frees_the_handler() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let finished = StdArc::new(AtomicBool::new(false));
    let probe_finished = finished.clone();
    let probe = serve_streaming(&socket, move |_request, sender| {
        let finished = probe_finished.clone();
        async move {
            // 先推一条，然后持续推送；客户端在第一条后断开，
            // 后续 send 失败必须让 handler 退出（finished 置位）。
            let _ = sender.send(Response::Ok { id: 1, result: json!({"step": 1}) }).await;
            for step in 2..1000u64 {
                if sender
                    .send(Response::Ok {
                        id: 1,
                        result: json!({ "step": step }),
                    })
                    .await
                    .is_err()
                {
                    finished.store(true, Ordering::SeqCst);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    })
    .await;
    wait_for_socket(&socket).await;

    let mut rx = ipc::request_stream(&socket, Request::new(1, "test.stream", json!({})))
        .await
        .unwrap();
    let first = rx.recv().await.expect("应收到第一条");
    assert!(matches!(first, Response::Ok { .. }));
    drop(rx); // 客户端断开

    for _ in 0..100 {
        if finished.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        finished.load(Ordering::SeqCst),
        "客户端断开后 handler 应停止推送并退出"
    );

    // 同一 hzd 的其他连接不受影响：普通一问一答照常。
    let response = ipc::request(&socket, Request::new(2, "status", json!({})))
        .await
        .unwrap();
    assert_eq!(
        response,
        Response::Ok {
            id: 2,
            result: json!({"single": true})
        }
    );
    probe.stop().await;
}

/// 1 MiB 单行上限对流中每一行同样生效：超限行断开连接，其后的行到不了对端。
#[tokio::test]
async fn oversized_stream_line_is_rejected_per_line() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let probe = serve_streaming(&socket, |_request, sender| async move {
        let _ = sender
            .send(Response::Ok {
                id: 1,
                result: json!({"step": 1}),
            })
            .await;
        // 超过 1 MiB 的单行：写侧必须拒绝（客户端侧 read_line_capped 也会拦）。
        let _ = sender
            .send(Response::Ok {
                id: 1,
                result: json!({ "blob": "x".repeat(2 * 1024 * 1024) }),
            })
            .await;
        let _ = sender
            .send(Response::Ok {
                id: 1,
                result: json!({"step": 3}),
            })
            .await;
    })
    .await;
    wait_for_socket(&socket).await;

    let mut rx = ipc::request_stream(&socket, Request::new(1, "test.stream", json!({})))
        .await
        .unwrap();
    let mut steps = Vec::new();
    while let Some(response) = rx.recv().await {
        if let Response::Ok { result, .. } = response {
            steps.push(result["step"].as_u64().unwrap_or(0));
        }
    }
    probe.stop().await;
    assert_eq!(
        steps,
        vec![1],
        "超限行之后的响应不应到达客户端，实际收到 {steps:?}"
    );
}

/// 流式方法不受单次请求 30 秒超时约束：推送前先等待也能收到
///（对照 `request` 的 REQUEST_TIMEOUT 包装，这里没有整体限时）；
/// 同一服务上的一问一答方法行为不变。
#[tokio::test]
async fn streaming_waits_are_not_bounded_by_the_single_shot_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let probe = serve_streaming(&socket, |request, sender| async move {
        // 比 IPC 测试通常的节奏长、足以证明没有短超时截断；不真等 30s。
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = sender
            .send(Response::Ok {
                id: request.id,
                result: json!({"after": "wait"}),
            })
            .await;
    })
    .await;
    wait_for_socket(&socket).await;

    let mut rx = ipc::request_stream(&socket, Request::new(9, "test.stream", json!({})))
        .await
        .unwrap();
    let response = rx.recv().await.expect("等待后的推送应到达");
    assert!(
        matches!(response, Response::Ok { id: 9, .. }),
        "{response:?}"
    );
    drop(rx);

    let single = ipc::request(&socket, Request::new(10, "status", json!({})))
        .await
        .unwrap();
    assert_eq!(
        single,
        Response::Ok {
            id: 10,
            result: json!({"single": true})
        },
        "一问一答方法与流式方法并存时行为不变"
    );
    probe.stop().await;
}
