//! `hz ping` 与 `hz status` 对端表的 CLI 渲染：对着一个按 hzd IPC 契约
//! 应答的假守护进程跑真实二进制，断言用户可见文案。

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use hz_core::ipc;
use serde_json::json;

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
async fn ping_prints_round_trip_and_direct_path() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let server = tokio::spawn({
        let socket = socket.clone();
        async move {
            ipc::serve(
                &socket,
                ipc::handler(|_request: ipc::Request| async {
                    Ok(json!({
                        "name": "hznodeb",
                        "rtt_ms": 12.34,
                        "path": "direct",
                        "endpoint": "203.0.113.11:40101",
                    }))
                }),
            )
            .await
        }
    });
    wait_for_socket(&socket).await;

    let output = hz_binary()
        .env("HZD_SOCK_PATH", &socket)
        .arg("ping")
        .arg("hznodeb")
        .output()
        .unwrap();
    server.abort();

    assert!(
        output.status.success(),
        "stderr：{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "hznodeb 往返 12.3 ms，路径 Direct Path（IPv4 203.0.113.11:40101）"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ping_prints_relayed_path_without_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let server = tokio::spawn({
        let socket = socket.clone();
        async move {
            ipc::serve(
                &socket,
                ipc::handler(|_request: ipc::Request| async {
                    Ok(json!({
                        "name": "hznodeb",
                        "rtt_ms": 45.67,
                        "path": "relay",
                        "endpoint": null,
                    }))
                }),
            )
            .await
        }
    });
    wait_for_socket(&socket).await;

    let output = hz_binary()
        .env("HZD_SOCK_PATH", &socket)
        .arg("ping")
        .arg("hznodeb")
        .output()
        .unwrap();
    server.abort();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "hznodeb 往返 45.7 ms，路径 Relayed Path"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ping_surfaces_daemon_error_and_fails() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let server = tokio::spawn({
        let socket = socket.clone();
        async move {
            ipc::serve(
                &socket,
                ipc::handler(|_request: ipc::Request| async {
                    Err::<serde_json::Value, _>("hznodeb 无应答（3 次尝试）".to_string())
                }),
            )
            .await
        }
    });
    wait_for_socket(&socket).await;

    let output = hz_binary()
        .env("HZD_SOCK_PATH", &socket)
        .arg("ping")
        .arg("hznodeb")
        .output()
        .unwrap();
    server.abort();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("无应答"), "stderr 实际内容：{stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn status_prints_peer_table_with_path_endpoint_and_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let server = tokio::spawn({
        let socket = socket.clone();
        async move {
            ipc::serve(
                &socket,
                ipc::handler(|request: ipc::Request| async move {
                    assert_eq!(request.method, "status");
                    Ok(json!({
                        "registered": true,
                        "node_id": "n1",
                        "name": "hznodea",
                        "ipv4": "100.96.0.1",
                        "ipv6": "fd00::96:1",
                        "tags": [],
                        "peers": [
                            {
                                "name": "hznodeb",
                                "ipv4": "100.96.0.2",
                                "ipv6": "fd00::96:2",
                                "endpoints": ["203.0.113.9:41001"],
                                "handshake_secs": 5,
                                "path": "relay",
                                "endpoint": null,
                            },
                            {
                                "name": "hznodec",
                                "ipv4": "100.96.0.3",
                                "ipv6": "fd00::96:3",
                                "endpoints": ["[2001:db8::3]:51820"],
                                "handshake_secs": null,
                                "path": "direct",
                                "endpoint": "[2001:db8::3]:51820",
                            },
                        ],
                        "dns_suffix": "hznet.internal",
                    }))
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

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("hznodeb | 100.96.0.2 / fd00::96:2 | Relayed Path | - | 5 秒前"),
        "实际输出：\n{stdout}"
    );
    assert!(
        stdout.contains(
            "hznodec | 100.96.0.3 / fd00::96:3 | Direct Path (IPv6) | [2001:db8::3]:51820 | 从未"
        ),
        "实际输出：\n{stdout}"
    );
    assert!(
        stdout.contains("Node Name | Node Address | 路径 | Endpoint | 最近握手"),
        "实际输出：\n{stdout}"
    );
}
