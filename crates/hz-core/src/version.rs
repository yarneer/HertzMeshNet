//! 构建期版本。`hz` / `hzd --version` 共用 [`cli_version_line`]；
//! Hello 的 `node_version` 复用 [`version_string`]（规格 §3、§7 OB-8）。

/// 语义化版本；能读到 git 时附上短 commit，例如 `0.3.0 (a1b2c3d)`。没有 git 时只有版本号。
/// Hello 的 `node_version` 复用这个字符串。
pub fn version_string() -> &'static str {
    env!("HZ_VERSION_STRING")
}

/// `hz --version` 与 `hzd --version` 打印的同一行，例如 `hzd 0.3.0 (a1b2c3d)`。
pub fn cli_version_line() -> &'static str {
    env!("HZ_CLI_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_line_is_hzd_prefixed_version_string() {
        assert_eq!(cli_version_line(), format!("hzd {}", version_string()));
    }

    #[test]
    fn version_string_is_semver_with_optional_short_commit() {
        let version = version_string();
        let semver = match version.split_once(' ') {
            None => version,
            Some((semver, rest)) => {
                let sha = rest
                    .strip_prefix('(')
                    .and_then(|rest| rest.strip_suffix(')'))
                    .unwrap_or_else(|| panic!("commit 应写成 (sha)，实际 {version}"));
                assert!(
                    sha.len() >= 7 && sha.chars().all(|c| c.is_ascii_hexdigit()),
                    "{sha}"
                );
                semver
            }
        };
        assert_eq!(semver, env!("CARGO_PKG_VERSION"));
    }
}
