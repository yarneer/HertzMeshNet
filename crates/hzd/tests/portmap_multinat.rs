//! Seam B（#77，进程内）：模拟的 NAT-PMP 网关返回**私网**地址（192.168.x，
//! 实测 MiWiFi 双重 NAT 的形态）→ 不上报 PortMap 候选，netcheck 提示多重
//! NAT。独立测试二进制：HZD_PORTMAP_GATEWAY 只影响本进程。

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

/// NAT-PMP 应答桩：外网地址 192.168.115.116（路由器上游还有 NAT）。
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
            let external: Ipv4Addr = "192.168.115.116".parse().unwrap();
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
async fn private_portmap_external_is_not_reported_and_netcheck_hints_multi_nat() {
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

    // 给映射任务与两轮 Endpoint 收集留时间（PCP 超时 + 收集周期）。
    tokio::time::sleep(Duration::from_secs(8)).await;
    let endpoints: String = sqlx::query_scalar("SELECT udp_endpoints FROM nodes WHERE id = ?1")
        .bind(&granted.node_id)
        .fetch_one(store.pool())
        .await
        .unwrap_or_default();
    assert!(
        !endpoints.contains("portmap"),
        "私网外网地址不得作为 PortMap 候选上报：{endpoints}"
    );

    let netcheck = ipc::request(&socket, Request::new(1, "netcheck", serde_json::json!({})))
        .await
        .unwrap();
    match netcheck {
        Response::Ok { result, .. } => {
            assert_eq!(result["portmap"]["protocol"], "NAT-PMP", "{result}");
            assert_eq!(
                result["portmap"]["external"], "192.168.115.116",
                "多重 NAT 只展示外网地址（无端口，候选未上报）：{result}"
            );
            assert_eq!(result["portmap"]["multi_nat"], true, "{result}");
        }
        Response::Error { error, .. } => panic!("netcheck 失败：{error}"),
    }

    daemon.abort();
    let _ = daemon.await;
    coord.shutdown();
}
