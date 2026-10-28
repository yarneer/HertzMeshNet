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
