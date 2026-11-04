//! hzd 的 log_tail 来源（桌面）：`HZD_LOG_FILE` 显式指定（测试与手工部署）、
//! `HZD_JOURNAL_FILE`（测试注入 journal 管道）或 Linux systemd journal；
//! macOS 默认取 launchd plist 的 StandardErrorPath。尾部读取、脱敏与预算
//! 的管线在 `hz_engine::diagnostics`（Android 共用），这里只做来源选择。
//! 载荷的 schema_version / collected_at / 整包二次脱敏见引擎侧。

use std::path::PathBuf;

pub use hz_engine::diagnostics::{
    LOG_TAIL_LINES, SCHEMA_VERSION, collect_tail_from_path, collected_at_utc, redact_line,
    redact_lines,
};

/// hzd 日志文件路径：`HZD_LOG_FILE` 显式指定，否则按平台默认（macOS 是
/// launchd plist 的 StandardErrorPath）。Linux 的默认落在 systemd journal。
/// `HZD_JOURNAL_FILE` 注入时返回 None，让 macOS 默认路径也让开，注入才能
/// 进 journal 管道。
fn hzd_log_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("HZD_LOG_FILE") {
        return Some(PathBuf::from(path));
    }
    if std::env::var_os("HZD_JOURNAL_FILE").is_some() {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        Some(PathBuf::from(crate::launchd::LOG_PATH))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// 读取日志尾部并逐行脱敏（hzd 的诊断入口；来源见模块注释）。
pub fn collect_log_tail() -> (Vec<String>, Option<String>) {
    collect_log_tail_from(hzd_log_path().as_deref())
}

/// 同 [`collect_log_tail`]，路径可注入（测试用）。None 时读
/// `HZD_JOURNAL_FILE`（测试注入）或 Linux 的 systemd journal，与文件路径
/// 共用引擎的 [`hz_engine::diagnostics::finish_tail`] 管线。
pub fn collect_log_tail_from(path: Option<&std::path::Path>) -> (Vec<String>, Option<String>) {
    if let Some(path) = path {
        return collect_tail_from_path(path);
    }
    if let Some(lines) = journal_tail() {
        let count = lines.len();
        return (
            lines,
            Some(format!(
                "最近 {count} 行（systemd journal hzd 服务，已脱敏）"
            )),
        );
    }
    #[cfg(target_os = "linux")]
    {
        (
            Vec::new(),
            Some("未配置 HZD_LOG_FILE 且 systemd journal 不可用，log_tail 为空".to_string()),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        (
            Vec::new(),
            Some("未配置 HZD_LOG_FILE，log_tail 为空".to_string()),
        )
    }
}

/// `HZD_JOURNAL_FILE`（测试注入）或 Linux `journalctl -u hzd` 的原文，再走
/// 引擎的 [`hz_engine::diagnostics::finish_tail`]。读不到则为 None。
fn journal_tail() -> Option<Vec<String>> {
    if let Some(path) = std::env::var_os("HZD_JOURNAL_FILE") {
        let text = std::fs::read_to_string(path).ok()?;
        return Some(hz_engine::diagnostics::finish_tail(&text));
    }
    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("journalctl")
            .args([
                "--unit",
                "hzd",
                "--no-pager",
                "--output",
                "cat",
                "--lines",
                &LOG_TAIL_LINES.to_string(),
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        Some(hz_engine::diagnostics::finish_tail(&text))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hz_engine::diagnostics::{MAX_LINE_CHARS, MAX_TAIL_BYTES};

    struct ClearEnv(&'static str);
    impl Drop for ClearEnv {
        fn drop(&mut self) {
            unsafe { std::env::remove_var(self.0) };
        }
    }

    #[test]
    fn journal_path_redacts_truncates_and_fits_budget() {
        let pem_body = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA";
        let hex = "ab".repeat(40);
        let mut raw = String::new();
        for i in 0..80 {
            raw.push_str(&format!("old-{i:03} {}\n", "o".repeat(7000)));
        }
        raw.push_str("-----BEGIN PRIVATE KEY-----\n");
        raw.push_str(pem_body);
        raw.push('\n');
        raw.push_str("morebase64bodyline==\n");
        raw.push_str("-----END PRIVATE KEY-----\n");
        raw.push_str(&format!(
            "journal-long {hex} {}\n",
            "L".repeat(MAX_LINE_CHARS + 100)
        ));
        raw.push_str("journal-newest endpoint=203.0.113.9:41001\n");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.log");
        std::fs::write(&path, raw).unwrap();
        // 走 daemon 同一入口。macOS 默认有 launchd 路径，必须仍能读到注入。
        let _unset = ClearEnv("HZD_JOURNAL_FILE");
        unsafe {
            std::env::remove_var("HZD_LOG_FILE");
            std::env::set_var("HZD_JOURNAL_FILE", &path);
        }
        let (tail, note) = collect_log_tail();

        let joined = tail.join("\n");
        assert!(!joined.contains(pem_body), "{joined}");
        assert!(!joined.contains("morebase64"), "{joined}");
        assert!(!joined.contains("BEGIN PRIVATE KEY"), "{joined}");
        assert!(!joined.contains(&hex), "{joined}");
        let long = tail
            .iter()
            .find(|line| line.contains("journal-long"))
            .expect("超长行应留下");
        assert!(long.ends_with("…(截断)"), "{long}");
        assert!(
            long.chars().count() <= MAX_LINE_CHARS + 10,
            "{}",
            long.chars().count()
        );
        assert!(joined.contains("journal-newest"), "{joined}");
        assert!(joined.contains("203.0.113.9:41001"), "{joined}");
        assert!(!joined.contains("old-000"), "预算应丢掉最老行：{joined}");
        let total: usize = tail.iter().map(|line| line.len() + 2).sum();
        assert!(total <= MAX_TAIL_BYTES, "{total}");
        let note = note.expect("journal 说明");
        assert!(
            note.contains("已脱敏") && note.contains("journal"),
            "{note}"
        );
        assert!(note.contains(&format!("最近 {} 行", tail.len())), "{note}");
    }
}
