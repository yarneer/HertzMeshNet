//! 把 git 短哈希编进 hz-core（#70）：`hzd --version` / Hello 上报复用同一
//! 字符串。取不到 git（源码包构建、精简 CI 容器）时什么都不注入，
//! version.rs 按"无 commit"降级，构建不失败。

fn main() {
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        && output.status.success()
    {
        let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !sha.is_empty() {
            println!("cargo:rustc-env=HZ_GIT_COMMIT={sha}");
        }
    }
}
