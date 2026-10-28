use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use hz_core::ipc;

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

fn sample_report() -> serde_json::Value {
    serde_json::json!({
        "egress": {
            "physical": "eth0",
            "default_route": "utun4",
            "virtual_holds_default": true
        },
        "udp": {
            "ipv4": {"ok": false, "stage": "send", "error": "EINVAL", "mapped": null},
            "ipv6": {"ok": true, "stage": null, "error": null, "mapped": "[2001:db8::8]:51820"}
        },
        "stun": {"targets": 1, "mapped": ["[2001:db8::8]:51820"], "nat": "无法判断"},
        "endpoints": [{
            "addr": "198.18.0.1:51820",
            "kind": "lan",
            "suspicious": ["198.18.0.0/15", "virtual_nic"]
        }],
        "ipv6_usable": false,
        "relay_rtt_ms": null,
        "peers": [{
            "name": "mini",
            "node_id": "n-mini",
            "path": "relay",
            "punch": "attempted"
        }]
    })
}

async fn run_netcheck(args: &[&str]) -> (bool, String, String) {
    let report = sample_report();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("hzd.sock");
    let server = tokio::spawn({
        let socket = socket.clone();
        async move {
            ipc::serve(
                &socket,
                ipc::handler(move |request: ipc::Request| {
                    let report = report.clone();
                    async move {
                        if request.method == "netcheck" {
                            Ok(report)
                        } else {
                            Err(format!("unexpected method {}", request.method))
                        }
                    }
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
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn netcheck_json_round_trips_the_report() {
    let (ok, stdout, stderr) = run_netcheck(&["netcheck", "--json"]).await;
    assert!(ok, "{stderr}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed, sample_report());
}

#[tokio::test(flavor = "multi_thread")]
async fn netcheck_text_shows_einval_and_fake_lan() {
    let (ok, stdout, stderr) = run_netcheck(&["netcheck"]).await;
    assert!(ok, "{stderr}{stdout}");
    assert!(
        stdout.contains("IPv4 UDP 外发失败：EINVAL"),
        "应直接显示底层错误：{stdout}"
    );
    assert!(
        stdout.contains("⚠ LAN Endpoint 198.18.0.1:51820 落在 198.18.0.0/15"),
        "LAN 假地址应告警：{stdout}"
    );
    assert!(stdout.contains("虚拟网卡持有"), "{stdout}");
    assert!(stdout.contains("NAT：无法判断"), "{stdout}");
}

#[test]
fn netcheck_fails_fast_when_daemon_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("absent.sock");
    let started = Instant::now();
    let output = hz_binary()
        .env("HZD_SOCK_PATH", &socket)
        .arg("netcheck")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(started.elapsed() < Duration::from_secs(5));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("无法连接 hzd"), "{stderr}");
}
