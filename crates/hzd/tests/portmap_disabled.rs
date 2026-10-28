//! Seam B（#77，进程内）：`HZD_PORTMAP=0` 关闭后 hzd 不发起任何端口映射
//! 请求（桩网关一个报文都收不到），netcheck 显示「不可用」。独立测试二进制：
//! 环境变量只影响本进程。

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, serve};
use hz_coord::store::Store;
use hz_core::ipc::{self, Request, Response};
use hz_core::status::RegisteredInfo;

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
async fn portmap_disabled_sends_no_requests_at_all() {
    // 桩网关：收到的每个报文都计数（不应有任何报文）。
    let received: Arc<Mutex<Vec<usize>>> = Arc::new(Mutex::new(Vec::new()));
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let gateway = sock.local_addr().unwrap();
    let server = {
        let sock = Arc::new(sock);
        let received = received.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let Ok((len, _)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                received.lock().unwrap().push(len);
            }
        })
    };
    // SAFETY: 本二进制只有这一个测试线程，daemon 尚未启动，无并发读写。
    unsafe {
        std::env::set_var("HZD_PORTMAP_GATEWAY", gateway.to_string());
        std::env::set_var("HZD_PORTMAP", "0");
    }

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
    let socket = node_dir.path().join("hzd.sock");
    let daemon = tokio::spawn(hzd::run(node_dir.path().to_path_buf(), socket.clone()));
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
    match up {
        Response::Ok { result, .. } => {
            let _ = serde_json::from_value::<RegisteredInfo>(result).unwrap();
        }
        Response::Error { error, .. } => panic!("hz up 失败：{error}"),
    }

    // 留足映射任务本来会发起请求的时间（PCP 2s 超时 + NAT-PMP + SSDP）。
    tokio::time::sleep(Duration::from_secs(6)).await;
    server.abort();
    assert!(
        received.lock().unwrap().is_empty(),
        "HZD_PORTMAP=0 不得发出任何端口映射请求，实际收到 {:?}",
        received.lock().unwrap()
    );

    let netcheck = ipc::request(&socket, Request::new(1, "netcheck", serde_json::json!({})))
        .await
        .unwrap();
    match netcheck {
        Response::Ok { result, .. } => {
            assert_eq!(
                result["portmap"]["protocol"],
                serde_json::Value::Null,
                "{result}"
            );
            assert_eq!(result["portmap"]["multi_nat"], false, "{result}");
        }
        Response::Error { error, .. } => panic!("netcheck 失败：{error}"),
    }

    daemon.abort();
    let _ = daemon.await;
    coord.shutdown();
}
