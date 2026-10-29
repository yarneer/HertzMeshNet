//! Seam B（#83）：真实 hzd + 进程内 coord + 真实 UDS。subscribe 在注册
//! 完成、down、up 时各推一份反映新状态的快照；连续变化的推送间隔不小于
//! 1 秒；空闲时收到 15 秒心跳。交互式登录完成与 Auth Key 注册共用同一
//! finish_registration 路径，此处以注册覆盖。

use std::path::Path;
use std::time::{Duration, Instant};

use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, serve};
use hz_coord::store::Store;
use hz_core::ipc::{self, Request, Response};
use tokio::sync::mpsc;

async fn wait_for_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("socket {} never appeared", path.display());
}

async fn call(socket: &Path, id: u64, method: &str) -> Result<serde_json::Value, String> {
    match ipc::request(socket, Request::new(id, method, serde_json::json!({})))
        .await
        .unwrap()
    {
        Response::Ok { result, .. } => Ok(result),
        Response::Error { error, .. } => Err(error),
    }
}

/// 在订阅流上等待一份满足 `pred` 的快照；返回 (快照, 收到时刻)。
/// 顺带记录途中每份快照的到达时刻（供间隔断言）。
async fn wait_for_snapshot(
    rx: &mut mpsc::Receiver<Response>,
    stamps: &mut Vec<Instant>,
    pred: impl Fn(&serde_json::Value) -> bool,
    label: &str,
) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or_default();
        let received =
            match tokio::time::timeout(remaining.max(Duration::from_millis(50)), rx.recv()).await {
                Ok(Some(response)) => response,
                Ok(None) => panic!("订阅流意外结束（等待 {label} 时）"),
                Err(_) => panic!("30 秒内未等到 {label} 的快照"),
            };
        let Response::Ok { result, .. } = received else {
            panic!("订阅推了错误响应（等待 {label} 时）：{received:?}")
        };
        stamps.push(Instant::now());
        if pred(&result) {
            return result;
        }
    }
}

fn desired(result: &serde_json::Value) -> &str {
    result["desired_state"].as_str().unwrap_or("")
}

#[tokio::test]
async fn subscribe_pushes_snapshots_for_up_down_up_and_heartbeats() {
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

    // 订阅建立：立即收到第一份（未注册）快照。
    let mut rx = ipc::request_stream(&socket, Request::new(9, "subscribe", serde_json::json!({})))
        .await
        .unwrap();
    let mut stamps = Vec::new();
    let first = wait_for_snapshot(
        &mut rx,
        &mut stamps,
        |v| v["registered"].is_boolean(),
        "首份快照",
    )
    .await;
    assert_eq!(first["registered"], false, "订阅建立时未注册：{first}");
    assert_eq!(desired(&first), "up", "缺省 Desired State 为 up：{first}");

    // 注册完成：收到带身份、desired_state=up 的完整快照。
    let up = tokio::spawn({
        let socket = socket.clone();
        let coord_addr = coord_addr.clone();
        let auth_key = auth_key.clone();
        async move {
            ipc::request(
                &socket,
                Request::new(
                    1,
                    "up",
                    serde_json::json!({ "auth_key": auth_key, "coord_addr": coord_addr }),
                ),
            )
            .await
            .unwrap()
        }
    });
    let registered = wait_for_snapshot(
        &mut rx,
        &mut stamps,
        |v| v["registered"] == true && v["desired_state"] == "up" && v["peers"].is_array(),
        "注册完成快照",
    )
    .await;
    let name = registered["name"].as_str().unwrap().to_string();
    let _ = up.await;

    // down：快照翻为 desired_state=down（身份保留）。
    tokio::spawn({
        let socket = socket.clone();
        async move { ipc::request(&socket, Request::new(2, "down", serde_json::json!({}))).await }
    });
    let down_snapshot =
        wait_for_snapshot(&mut rx, &mut stamps, |v| desired(v) == "down", "down 快照").await;
    assert_eq!(
        down_snapshot["name"].as_str(),
        Some(name.as_str()),
        "身份保留"
    );

    // up（已注册恢复）：翻回 up。
    tokio::spawn({
        let socket = socket.clone();
        async move { ipc::request(&socket, Request::new(3, "up", serde_json::json!({}))).await }
    });
    wait_for_snapshot(&mut rx, &mut stamps, |v| desired(v) == "up", "恢复 up 快照").await;

    // 连续触发的多次变化：相邻推送间隔不小于 1 秒（1 秒节拍合并抖动）。
    // 上面已积累全部推送时刻；额外快速连打两次 down/up 再核对间隔下限。
    for method in ["down", "up"] {
        let socket2 = socket.clone();
        tokio::spawn(async move {
            let _ = ipc::request(&socket2, Request::new(4, method, serde_json::json!({}))).await;
        })
        .await
        .unwrap();
    }
    wait_for_snapshot(
        &mut rx,
        &mut stamps,
        |v| desired(v) == "up",
        "快速连打后的终态",
    )
    .await;
    let min_gap = stamps
        .windows(2)
        .map(|pair| pair[1].duration_since(pair[0]))
        .min()
        .unwrap();
    assert!(
        min_gap >= Duration::from_millis(950),
        "相邻推送间隔应 ≥ 1 秒（含调度余量），实际最小 {min_gap:?}（共 {} 份）",
        stamps.len()
    );

    // 空闲心跳：不再做任何操作，15 秒节拍内收到一份与当前相同的快照。
    let before_beats = stamps.len();
    let idle_start = Instant::now();
    let heartbeat = wait_for_snapshot(&mut rx, &mut stamps, |_| true, "空闲心跳").await;
    let waited = idle_start.elapsed();
    assert_eq!(desired(&heartbeat), "up");
    assert!(
        waited + Duration::from_secs(2) >= Duration::from_secs(15),
        "空闲期的推送应是 ~15 秒心跳，实际 {waited:?} 就来了一份（前 {before_beats} 份之后）"
    );
    assert!(
        waited <= Duration::from_secs(20),
        "心跳不应超过 15 秒节拍 + 余量，实际等了 {waited:?}"
    );

    // 第二个订阅者并存：互不影响，各自收到快照；hzd 存活。
    let mut second = ipc::request_stream(
        &socket,
        Request::new(10, "subscribe", serde_json::json!({})),
    )
    .await
    .unwrap();
    let mut second_stamps = Vec::new();
    let second_first = wait_for_snapshot(
        &mut second,
        &mut second_stamps,
        |v| v["registered"] == true && desired(v) == "up",
        "第二订阅者首份",
    )
    .await;
    assert_eq!(second_first["name"].as_str(), Some(name.as_str()));

    // 订阅者断开不影响 hzd：drop 两个订阅后，普通一问一答仍正常应答。
    drop(rx);
    drop(second);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let still = call(&socket, 5, "status")
        .await
        .expect("hzd 应在订阅者断开后存活");
    assert_eq!(still["name"].as_str(), Some(name.as_str()));

    daemon.abort();
    let _ = daemon.await;
    coord.shutdown();
}
