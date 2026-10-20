use std::path::Path;
use std::process::Command;
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
                ipc::handler(|_request: ipc::Request| async {
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

// `hz status | grep -q …` 里 grep 先退出时，hz 写 stdout 会遇到断管：
// 必须像普通 Unix 工具一样被 SIGPIPE 静默终止，而不是 panic（Seam A 偶发失败的根因）。
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn status_exits_quietly_when_stdout_reader_is_gone() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;

    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let server = tokio::spawn({
        let socket = socket.clone();
        async move {
            ipc::serve(
                &socket,
                ipc::handler(|_request: ipc::Request| async {
                    serde_json::to_value(NodeStatus::Unregistered).map_err(|e| e.to_string())
                }),
            )
            .await
        }
    });
    wait_for_socket(&socket).await;

    let mut child = hz_binary()
        .env("HZD_SOCK_PATH", &socket)
        .arg("status")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // hz 先连 socket 再输出，读端在它写之前就已关闭，断管必然发生。
    drop(child.stdout.take());
    let output = child.wait_with_output().unwrap();
    server.abort();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "hz 不应 panic，stderr：{stderr}"
    );
    assert_eq!(
        output.status.signal(),
        Some(libc::SIGPIPE),
        "hz 应被 SIGPIPE 终止，实际：{:?}",
        output.status
    );
}

// #25：hz status 的冲突自检。假 hzd 给出本机 Node Address 与 HzNet 段，hz 对
// 段内地址做不发包的 UDP connect 读出系统选定的源地址：段为 127.0.0.0/8 时
// 源地址必为 127.0.0.1，本机 Node Address 设成别的地址即可确定性地构造
// "流量没有走 HzNet 网卡"。
async fn status_output(status: serde_json::Value, args: &[&str]) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let server = tokio::spawn({
        let socket = socket.clone();
        async move {
            ipc::serve(
                &socket,
                ipc::handler(move |_request: ipc::Request| {
                    let status = status.clone();
                    async move { Ok(status) }
                }),
            )
            .await
        }
    });
    wait_for_socket(&socket).await;
    let output = hz_binary()
        .env("HZD_SOCK_PATH", &socket)
        .args(args)
        .output()
        .unwrap();
    server.abort();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string()
            + &String::from_utf8_lossy(&output.stderr),
    )
}

/// 已注册状态夹具。HzNet 段设为 127.0.0.0/8：探测地址落在回环上，系统选定
/// 的源地址必为 127.0.0.1，与本机 Node Address 比较的结果因此确定。
fn registered(own_v4: &str) -> serde_json::Value {
    serde_json::json!({
        "registered": true,
        "node_id": "n-self",
        "name": "mac",
        "ipv4": own_v4,
        "ipv6": "fd7a:3548:1873::2",
        "tags": [],
        "network_cidr": "127.0.0.0/8",
        "dns_suffix": "invalid",
        "peers": [{ "name": "srv", "ipv4": "127.0.0.9", "ipv6": "fd7a:3548:1873::1", "path": "direct" }],
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn status_warns_when_hznet_traffic_leaves_from_another_interface() {
    let (ok, out) = status_output(registered("10.213.0.2"), &["status"]).await;

    assert!(ok, "{out}");
    assert!(
        out.contains("第三方 TUN 类网络工具接管"),
        "应提示流量被接管：{out}"
    );
    assert!(out.contains("127.0.0.1"), "应给出实际源地址：{out}");
    assert!(
        out.contains("10.213.0.2"),
        "应给出期望的本机 Node Address：{out}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn status_stays_quiet_when_traffic_uses_the_node_address() {
    let (ok, out) = status_output(registered("127.0.0.1"), &["status"]).await;

    assert!(ok, "{out}");
    assert!(
        !out.contains("没有走 HzNet 网卡"),
        "无冲突时不应提示：{out}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn status_json_carries_structured_conflicts() {
    let (ok, out) = status_output(registered("10.213.0.2"), &["status", "--json"]).await;

    assert!(ok, "{out}");
    let value: serde_json::Value = serde_json::from_str(&out).expect("--json 输出应为 JSON");
    assert_eq!(
        value["conflicts"]["route_capture"]["source"], "127.0.0.1",
        "{out}"
    );
    assert_eq!(
        value["conflicts"]["route_capture"]["expected"], "10.213.0.2",
        "{out}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn status_reports_recent_route_repair_and_dns_fallback() {
    let mut status = registered("127.0.0.1");
    status["diagnostics"] = serde_json::json!({
        "route_repair": {
            "at": 1760900000,
            "cidr": "10.213.0.0/16",
            "previous": { "state": "taken_by", "interface": "en0" },
        },
        "dns_fallback": { "at": 1760900100, "host": "relay.example.com" },
    });

    let (ok, out) = status_output(status, &["status"]).await;

    assert!(ok, "{out}");
    assert!(
        out.contains("10.213.0.0/16") && out.contains("en0"),
        "应显示路由修复：{out}"
    );
    assert!(
        out.contains("relay.example.com") && out.contains("引导 DNS"),
        "应显示引导 DNS 回退：{out}"
    );
    assert!(out.contains("2025-10-19"), "时间应格式化为日期：{out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn status_omits_diagnostics_section_when_nothing_happened() {
    let (ok, out) = status_output(registered("127.0.0.1"), &["status"]).await;

    assert!(ok, "{out}");
    assert!(
        !out.contains("最近一次"),
        "未发生过修复/回退时不显示：{out}"
    );
}

// 审查 (c)2/(a)2：探测不依赖对端（按 HzNet 地址段取探测地址），提示与 JSON
// 给出需要在对方工具中排除的地址段（IPv4 段 + ULA /48）。
#[tokio::test(flavor = "multi_thread")]
async fn capture_is_detected_without_peers_and_names_ranges_to_exclude() {
    let mut status = registered("10.213.0.2");
    status["peers"] = serde_json::json!([]);

    let (ok, out) = status_output(status.clone(), &["status"]).await;
    assert!(ok, "{out}");
    assert!(
        out.contains("第三方 TUN 类网络工具接管"),
        "无对端时也应检测：{out}"
    );
    assert!(
        out.contains("127.0.0.0/8") && out.contains("fd7a:3548:1873::/48"),
        "应给出需排除的地址段：{out}"
    );

    let (_, json) = status_output(status, &["status", "--json"]).await;
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        value["conflicts"]["route_capture"]["exclude"],
        serde_json::json!(["127.0.0.0/8", "fd7a:3548:1873::/48"]),
        "{json}"
    );
}
