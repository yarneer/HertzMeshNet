//! #70：`hzd --version` / `-V` 打印版本并以 0 退出，不启动守护进程——
//! 不创建 socket、不写状态目录。

use std::path::Path;
use std::process::Command;

fn run_hzd(arg: &str, state_dir: &Path) -> (String, Option<i32>, bool) {
    let output = Command::new(env!("CARGO_BIN_EXE_hzd"))
        .arg(arg)
        .env("HZD_STATE_DIR", state_dir)
        .env("HZD_SOCK_PATH", state_dir.join("hzd.sock"))
        .output()
        .expect("启动 hzd 失败");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        output.status.code(),
        state_dir.join("hzd.sock").exists(),
    )
}

#[test]
fn version_flags_print_and_exit_without_starting_the_daemon() {
    let state = tempfile::tempdir().expect("临时目录创建失败");
    for arg in ["--version", "-V"] {
        let (stdout, code, socket_created) = run_hzd(arg, state.path());
        assert_eq!(code, Some(0), "{arg} 应以 0 退出，输出：{stdout}");
        assert!(
            stdout.starts_with("hzd ") && stdout.trim_end().len() > "hzd ".len(),
            "{arg} 输出应为 `hzd <semver>[ (<sha>)]`，实际：{stdout}"
        );
        let tail = stdout.trim_end().strip_prefix("hzd ").unwrap();
        let expected = hz_core::version::node_version();
        assert_eq!(tail, expected, "{arg} 与 hz-core 版本串一致");
        assert!(!socket_created, "{arg} 不得创建 socket（守护进程未启动）");
        assert!(
            state
                .path()
                .read_dir()
                .map(|mut it| it.next().is_none())
                .unwrap_or(true),
            "{arg} 不得写状态目录：{:?}",
            state
                .path()
                .read_dir()
                .map(|it| it.filter_map(Result::ok).collect::<Vec<_>>())
        );
    }
}

#[test]
fn version_string_carries_semver_and_optional_commit() {
    let version = hz_core::version::node_version();
    let semver = hz_core::version::semver();
    assert!(version.starts_with(semver));
    match hz_core::version::git_commit() {
        Some(sha) => assert_eq!(version, format!("{semver} ({sha})")),
        // 无 git 环境：构建不失败，输出省略括号部分。
        None => assert_eq!(version, semver),
    }
}
