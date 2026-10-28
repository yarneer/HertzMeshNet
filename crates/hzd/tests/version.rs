use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use hz_core::version;

fn assert_version_flag_does_not_start_daemon(flag: &str) {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let socket = dir.path().join("hzd.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_hzd"))
        .arg(flag)
        .env("HZD_STATE_DIR", &state)
        .env("HZD_SOCK_PATH", &socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let output = match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(output)) => output,
        other => {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            panic!("{flag} 未在 2 秒内退出（{other:?}），守护进程不该启动");
        }
    };

    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim_end(),
        version::cli_version_line()
    );
    assert!(
        output.stderr.is_empty(),
        "版本查询不应打日志，stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!state.exists(), "{flag} 不应创建 state 目录");
    assert!(!socket.exists(), "{flag} 不应创建 socket");
}

#[test]
fn version_flags_print_and_do_not_start_the_daemon() {
    assert_version_flag_does_not_start_daemon("--version");
    assert_version_flag_does_not_start_daemon("-V");
}
