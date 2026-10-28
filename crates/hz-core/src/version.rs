//! 版本字符串（#70 / OB-8）：`hzd --version`、`hz --version` 与 Hello 上报的
//! `node_version` 共用同一来源——语义化版本 + build.rs 注入的 git 短哈希。
//! 取不到 git 时（源码包构建）省略括号部分，格式退化为 `<semver>`。

/// 语义化版本（workspace version，全部二进制一致）。
pub fn semver() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// git 短哈希；build.rs 注入失败（无 git 环境）时为 None。
pub fn git_commit() -> Option<&'static str> {
    option_env!("HZ_GIT_COMMIT")
}

/// Hello 随报的 `node_version`：`0.3.0 (a1b2c3d)`，无 commit 时 `0.3.0`。
pub fn node_version() -> String {
    match git_commit() {
        Some(sha) => format!("{} ({})", semver(), sha),
        None => semver().to_string(),
    }
}

/// 命令行 `--version` 输出：`hzd 0.3.0 (a1b2c3d)`。
pub fn banner(program: &str) -> String {
    format!("{program} {}", node_version())
}

/// `std::env::consts` 的平台三元组（Hello 的 os / arch 字段）。
pub fn os() -> &'static str {
    std::env::consts::OS
}

pub fn arch() -> &'static str {
    std::env::consts::ARCH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_version_is_semver_with_optional_commit() {
        let version = node_version();
        assert!(
            version.starts_with(concat!(env!("CARGO_PKG_VERSION"))),
            "版本串以 semver 开头：{version}"
        );
        match git_commit() {
            Some(sha) => assert_eq!(version, format!("{} ({})", semver(), sha)),
            None => assert_eq!(version, semver()),
        }
    }

    #[test]
    fn banner_prefixes_program_name() {
        assert_eq!(banner("hzd"), format!("hzd {}", node_version()));
    }
}
