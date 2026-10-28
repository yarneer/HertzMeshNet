//! Seam B（#72）：真实 hzd + 真实 coord——注册后第一轮 Endpoint 收集（interval
//! 首跳立即执行）随 ReportEndpoints 上报 Health Report，coord 内存里能读到
//! netcheck 六项；Hello 上报的版本串同时落库。

use std::path::Path;
use std::time::Duration;

use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, serve};
use hz_coord::store::Store;
use hz_core::ipc::{self, Request, Response};
use hz_core::status::RegisteredInfo;
use sqlx::Row;

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
async fn hzd_reports_health_report_with_endpoint_collection() {
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

    let daemon = tokio::spawn(hzd::run(state_dir.clone(), socket.clone()));
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

    // Endpoint 收集的 interval 首跳立即执行；无 STUN 目标时探测直接结束。
    // 最多等 10 秒（STUN 解析重试的余量）。
    let mut report = None;
    for _ in 0..100 {
        if let Some(received) = coord.health.fresh_report(&granted.node_id) {
            report = Some(received);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let received = report.unwrap_or_else(|| panic!("hzd 应随 ReportEndpoints 上报 Health Report"));
    // 测试环境没有 STUN 目标：UDP 双族不 ok、无映射、NAT unknown，但报告结构完整。
    assert!(!received.report.udp4_ok, "{:?}", received.report);
    assert!(!received.report.udp6_ok, "{:?}", received.report);
    assert!(!received.report.has_stun_mapping, "{:?}", received.report);
    assert_eq!(received.report.nat, "unknown");
    assert_eq!(received.report.direct_peers, 0);
    assert!(received.report.relayed_peers.is_empty());
    assert!(!received.report.suspicious_endpoint);

    // Hello 上报的版本串（#71）与 hz-core 版本一致并落库。
    let row = sqlx::query("SELECT node_version, os, arch FROM nodes WHERE id = ?1")
        .bind(&granted.node_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        row.get::<String, _>("node_version"),
        hz_core::version::node_version()
    );
    assert_eq!(row.get::<String, _>("os"), std::env::consts::OS);
    assert_eq!(row.get::<String, _>("arch"), std::env::consts::ARCH);

    daemon.abort();
    let _ = daemon.await;
    coord.shutdown();
}
