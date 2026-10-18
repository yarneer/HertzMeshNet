use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hz_core::ipc;
use hz_core::status::NodeStatus;

fn hz_binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hz"))
}

async fn wait_for_socket(path: &Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("socket {} never appeared", path.display());
}

// 子进程阻塞等待期间，单线程 runtime 不会轮询 server 任务，必须用多线程 flavor。
#[tokio::test(flavor = "multi_thread")]
async fn status_shows_unregistered_against_a_live_daemon_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let server = tokio::spawn({
        let socket = socket.clone();
        async move {
            ipc::serve(
                &socket,
                Arc::new(|_request: ipc::Request| {
                    serde_json::to_value(NodeStatus::Unregistered).map_err(|e| e.to_string())
                }),
            )
            .await
        }
    });
    wait_for_socket(&socket).await;

    let output = hz_binary()
        .env("HZD_SOCK_PATH", &socket)
        .arg("status")
        .output()
        .unwrap();
    server.abort();

    assert!(
        output.status.success(),
        "stderr：{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim(), "未加入 HzNet");
}

#[test]
fn status_fails_fast_with_clear_error_when_daemon_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("absent.sock");
    let started = Instant::now();
    let output = hz_binary()
        .env("HZD_SOCK_PATH", &socket)
        .arg("status")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "hz 必须快速失败，实际耗时 {:?}",
        started.elapsed()
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("无法连接 hzd"), "stderr 实际内容：{stderr}");
}
