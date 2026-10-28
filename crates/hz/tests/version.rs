use std::process::Command;
use std::time::{Duration, Instant};

use hz_core::version;

#[test]
fn version_flags_match_hzd_and_do_not_touch_the_daemon_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("absent.sock");
    for flag in ["--version", "-V"] {
        let started = Instant::now();
        let output = Command::new(env!("CARGO_BIN_EXE_hz"))
            .arg(flag)
            .env("HZD_SOCK_PATH", &socket)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{flag} 耗时 {:?}",
            started.elapsed()
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim_end(),
            version::cli_version_line()
        );
        assert!(
            output.stderr.is_empty(),
            "stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(!socket.exists(), "hz --version 不应创建 socket");
}
