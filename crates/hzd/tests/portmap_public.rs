//! Seam B（#77，进程内）：模拟的 NAT-PMP 网关返回**公网**地址 → hzd 上报
//! `PortMap` 候选（nodes 表 udp_endpoints 出现 portmap 来源项），netcheck
//! 显示协议与外网地址。独立测试二进制：HZD_PORTMAP_GATEWAY 只影响本进程。

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
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

/// NAT-PMP 应答桩：外网地址 198.51.100.7（公网），映射端口 52001。
async fn spawn_natpmp_stub() -> SocketAddr {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let sock = std::sync::Arc::new(sock);
        let mut buf = [0u8; 1500];
        loop {
            let Ok((_, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let external: Ipv4Addr = "198.51.100.7".parse().unwrap();
            let reply = if buf[1] == 0 {
                let mut response = vec![0, 0x80, 0, 0];
                response.extend_from_slice(&0u32.to_be_bytes());
                response.extend_from_slice(&external.octets());
                response
            } else if buf[1] == 2 {
                let mut response = vec![0, 0x82, 0, 0];
                response.extend_from_slice(&0u32.to_be_bytes());
                response.extend_from_slice(&51820u16.to_be_bytes());
                response.extend_from_slice(&52001u16.to_be_bytes());
                response.extend_from_slice(&7200u32.to_be_bytes());
                response
            } else {
                continue;
            };
            let _ = sock.send_to(&reply, from).await;
        }
    });
    endpoint
}

#[tokio::test]
async fn public_portmap_external_is_reported_as_portmap_candidate() {
    let stub = spawn_natpmp_stub().await;
    // SAFETY: 本二进制只有这一个测试线程，daemon 尚未启动，无并发读写。
    unsafe { std::env::set_var("HZD_PORTMAP_GATEWAY", stub.to_string()) };

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
    let daemon = tokio::spawn(hzd::run(state_dir, socket.clone()));
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
    let granted = match up {
        Response::Ok { result, .. } => serde_json::from_value::<RegisteredInfo>(result).unwrap(),
        Response::Error { error, .. } => panic!("hz up 失败：{error}"),
    };

    // 端口映射任务先试 PCP（桩不答，超时 2s）再试 NAT-PMP；随后立即上报。
    let mut saw_portmap = false;
    for _ in 0..100 {
        let endpoints: String = sqlx::query_scalar("SELECT udp_endpoints FROM nodes WHERE id = ?1")
            .bind(&granted.node_id)
            .fetch_one(store.pool())
            .await
            .unwrap_or_default();
        if endpoints.contains("\"kind\":\"portmap\"") || endpoints.contains("\"kind\": \"portmap\"")
        {
            saw_portmap = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        saw_portmap,
        "公网映射应作为 PortMap 候选上报（udp_endpoints 含 portmap 项）"
    );

    // netcheck 显示协议与外网地址，未判多重 NAT。
    let netcheck = ipc::request(&socket, Request::new(1, "netcheck", serde_json::json!({})))
        .await
        .unwrap();
    match netcheck {
        Response::Ok { result, .. } => {
            assert_eq!(result["portmap"]["protocol"], "NAT-PMP", "{result}");
            assert!(
                result["portmap"]["external"]
                    .as_str()
                    .is_some_and(|external| external.starts_with("198.51.100.7:")),
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
