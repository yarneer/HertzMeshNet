//! hzd 侧 `netcheck` 查询接口：未拉起数据面时也返回完整报告，且不猜测 NAT。

use std::path::Path;
use std::time::Duration;

use hz_core::ipc::{self, Request, Response};

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
async fn idle_daemon_answers_netcheck_without_guessing_nat() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let daemon = tokio::spawn(hzd::run(dir.path().to_path_buf(), socket.clone()));
    wait_for_socket(&socket).await;

    let response = ipc::request(&socket, Request::new(1, "netcheck", serde_json::json!({})))
        .await
        .unwrap();
    daemon.abort();
    let _ = daemon.await;

    let Response::Ok { result, .. } = response else {
        panic!("unexpected error response: {response:?}");
    };
    assert!(result["egress"]["virtual_holds_default"].is_boolean());
    assert_eq!(result["udp"]["ipv4"]["ok"], false);
    assert_eq!(result["udp"]["ipv4"]["error"], "数据面未启动");
    assert_eq!(result["udp"]["ipv6"]["error"], "数据面未启动");
    assert_eq!(result["stun"]["nat"], "无法判断");
    assert!(result["stun"]["mapped"].as_array().unwrap().is_empty());
    assert!(result["endpoints"].is_array());
    assert!(result["peers"].is_array());
    assert!(result["ipv6_usable"].is_boolean());
    assert!(result["relay_rtt_ms"].is_null());
}
