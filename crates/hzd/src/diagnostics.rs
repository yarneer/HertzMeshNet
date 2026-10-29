//! 脱敏诊断导出（#84 / MC-4）：`hz diagnostics` 与 macOS Client App 的
//! 「导出诊断包」共用的 IPC 数据在这里组装。
//!
//! `log_tail` 为 hzd 日志最近 [`LOG_TAIL_LINES`] 行——日志文件普通用户未必
//! 可读，由 hzd（通常以 root 运行）代读。读不到（文件不存在 / 不可读 /
//! 非 systemd 环境）时为空并附说明，不报错。
//!
//! 脱敏（`redact_line`，纯函数）：去掉私钥、Auth Key、邀请码与登录 URL 中
//! 的 token；保留 Node Name、Node Address 与 Endpoint（排障需要）。

use std::path::PathBuf;

/// 诊断包里日志的最大行数。
pub const LOG_TAIL_LINES: usize = 2000;

/// 单行截断上限：tracing 正常行远短于此，防个别爆行撑爆 IPC 1 MiB 上限。
const MAX_LINE_CHARS: usize = 8 * 1024;

/// hzd 日志文件路径：`HZD_LOG_FILE` 显式指定（测试与手工部署），否则按
/// 平台默认（macOS 是 launchd plist 的 StandardErrorPath）。Linux 的默认
/// 落在 systemd journal，见 [`journal_tail`]。
fn hzd_log_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("HZD_LOG_FILE") {
        return Some(PathBuf::from(path));
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

/// 读取日志尾部并逐行脱敏。返回 (行列表, 说明)；读取失败时行为空、说明
/// 告知原因（不报错，规格 §3.4）。
pub fn collect_log_tail() -> (Vec<String>, Option<String>) {
    collect_log_tail_from(hzd_log_path().as_deref())
}

/// 同 [`collect_log_tail`]，路径可注入（测试用）。None 走平台默认的
/// journal 路径（Linux）或「未配置」。
pub fn collect_log_tail_from(path: Option<&std::path::Path>) -> (Vec<String>, Option<String>) {
    if let Some(path) = path {
        return match std::fs::read_to_string(path) {
            Ok(text) => {
                let lines = tail_lines(&text, LOG_TAIL_LINES);
                let count = lines.len();
                (
                    lines.into_iter().map(|line| redact_line(&line)).collect(),
                    Some(format!("最近 {count} 行（{}，已脱敏）", path.display())),
                )
            }
            Err(error) => (
                Vec::new(),
                Some(format!(
                    "日志不可读（{}：{error}），log_tail 为空",
                    path.display()
                )),
            ),
        };
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(lines) = journal_tail() {
            let count = lines.len();
            return (
                lines.into_iter().map(|line| redact_line(&line)).collect(),
                Some(format!(
                    "最近 {count} 行（systemd journal hzd 服务，已脱敏）"
                )),
            );
        }
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

/// 文本最后 `max` 行，每行截断到 [`MAX_LINE_CHARS`]。
fn tail_lines(text: &str, max: usize) -> Vec<String> {
    let mut lines: Vec<String> = text.lines().map(truncate_line).collect();
    if lines.len() > max {
        lines.drain(..lines.len() - max);
    }
    lines
}

fn truncate_line(line: &str) -> String {
    if line.chars().count() <= MAX_LINE_CHARS {
        line.to_string()
    } else {
        let head: String = line.chars().take(MAX_LINE_CHARS).collect();
        format!("{head}…(截断)")
    }
}

/// Linux 默认路径：systemd journal（hzd 通常由 systemd 托管，root 可读）。
#[cfg(target_os = "linux")]
fn journal_tail() -> Option<Vec<String>> {
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
    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_string)
            .collect(),
    )
}

const REDACTED: &str = "[REDACTED]";

/// 一行日志的脱敏（#84 验收：私钥 / Auth Key / 邀请码 / 登录 token 不出现，
/// Node Name / Node Address / Endpoint 保留）。规则按序应用：
///
/// 1. PEM 私钥块（`-----BEGIN … PRIVATE KEY-----`）整段替换；
/// 2. Auth Key / Relay Token：`hznet.` / `hzrelay.` 后的 base64url 主体；
/// 3. 邀请码：`HZ-XXXX-XXXX`；
/// 4. 登录 URL：`/oidc/start/<login_id>` 与 `login_id=<…>` 的 token 部分；
/// 5. 私钥的 hex 形态：连续 ≥64 个十六进制字符（Machine/Node Key 私钥
///    序列化后的典型形态；公钥同样命中，多脱不错）。
pub fn redact_line(line: &str) -> String {
    if line.contains("PRIVATE KEY") {
        return format!("…{REDACTED}（PEM 私钥块）");
    }
    let mut line = redact_prefixed_secret(line, "hznet.");
    line = redact_prefixed_secret(&line, "hzrelay.");
    line = redact_invite_codes(&line);
    line = redact_login_tokens(&line);
    redact_long_hex(&line)
}

/// `hznet.` / `hzrelay.` 后 ≥20 个 base64url 字符的实体替换为 [REDACTED]。
fn redact_prefixed_secret(line: &str, prefix: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(found) = rest.find(prefix) {
        let after = found + prefix.len();
        out.push_str(&rest[..after]);
        let tail = &rest[after..];
        let body_len = tail
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .count();
        if body_len >= 20 {
            out.push_str(REDACTED);
            rest = &tail[body_len..];
        } else {
            // 前缀后面不是密钥形态（如普通词），原样保留继续扫。
            let keep = body_len.min(tail.len());
            let (head, tail_rest) = tail.split_at(keep);
            out.push_str(head);
            rest = tail_rest;
        }
    }
    out.push_str(rest);
    out
}

/// `HZ-XXXX-XXXX`（32 位无歧义字母表）→ `HZ-[REDACTED]`。
fn redact_invite_codes(line: &str) -> String {
    const ALPHABET: &str = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let is_invite_char = |c: char| ALPHABET.contains(c);
    let mut out = String::with_capacity(line.len());
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == 'H'
            && i + 11 < chars.len()
            && chars[i + 1] == 'Z'
            && chars[i + 2] == '-'
            && chars[i + 3..i + 7].iter().all(|c| is_invite_char(*c))
            && chars[i + 7] == '-'
            && chars[i + 8..i + 12].iter().all(|c| is_invite_char(*c))
            && !is_invite_char(chars.get(i + 12).copied().unwrap_or('.'))
        {
            out.push_str("HZ-");
            out.push_str(REDACTED);
            i += 12;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// 登录 URL 与 login_id：`/oidc/start/<token>` → 路径段替换；
/// `login_id=<token>` → `login_id=[REDACTED]`。
fn redact_login_tokens(line: &str) -> String {
    let mut line = redact_after_marker(line, "/oidc/start/");
    line = redact_after_marker(&line, "login_id=");
    line
}

/// 把 marker 之后的 token 段（到下一个非 URL/标识符字符）替换为 [REDACTED]。
fn redact_after_marker(line: &str, marker: &str) -> String {
    let Some(found) = line.find(marker) else {
        return line.to_string();
    };
    let after = found + marker.len();
    let tail = &line[after..];
    let token_len = tail
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .count();
    if token_len == 0 {
        return line.to_string();
    }
    format!("{}{}{}", &line[..after], REDACTED, &tail[token_len..])
}

/// 连续 ≥64 个十六进制字符（私钥 hex 形态）→ [REDACTED]。
fn redact_long_hex(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(found) = rest.find(|c: char| c.is_ascii_hexdigit()) {
        let start = found;
        let end = rest[start..]
            .find(|c: char| !c.is_ascii_hexdigit())
            .map(|offset| start + offset)
            .unwrap_or(rest.len());
        let run = &rest[start..end];
        if run.len() >= 64 {
            out.push_str(&rest[..start]);
            out.push_str(REDACTED);
        } else {
            out.push_str(&rest[..end]);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_redacted_but_names_and_endpoints_survive() {
        // Auth Key（hznet.<43 base64url>）与 Relay Token。
        let line = "issued auth key hznet.c3VwZXJzZWNyZXRrZXlkb25vdGNoYXJlMTIz to user";
        let redacted = redact_line(line);
        assert!(
            !redacted.contains("c3VwZXJzZWNyZXRrZXlkb25vdGNoYXJl"),
            "{redacted}"
        );
        assert!(redacted.contains("hznet.[REDACTED]"), "{redacted}");
        let relay = redact_line("relay token hzrelay.c3VwZXJzZWNyZXRrZXlkb25vdGNoYXJlMTIz set");
        assert!(relay.contains("hzrelay.[REDACTED]"), "{relay}");

        // 邀请码。
        let invite = redact_line("invite HZ-ABCD-EFGH issued");
        assert_eq!(invite, "invite HZ-[REDACTED] issued");

        // 登录 URL 的 token 与 login_id。
        let login =
            redact_line("login_url=https://coord.example.com/oidc/start/n-a1b2c3d4e5f6a7b8");
        assert!(!login.contains("n-a1b2c3d4e5f6a7b8"), "{login}");
        assert!(login.contains("/oidc/start/[REDACTED]"), "{login}");
        let id = redact_line("login_id=n-a1b2c3d4e5f6a7b8c9d0e1f2 pending");
        assert!(id.contains("login_id=[REDACTED]"), "{id}");

        // 私钥：hex（≥64）与 PEM 块。
        let hex_key = format!("machine key priv {} loaded", "ab".repeat(40));
        let redacted = redact_line(&hex_key);
        assert!(!redacted.contains("ababab"), "{redacted}");
        assert!(redacted.contains(REDACTED), "{redacted}");
        let pem = redact_line("-----BEGIN PRIVATE KEY----- MIIB... -----END PRIVATE KEY-----");
        assert!(!pem.contains("MIIB"), "{pem}");

        // 保留：Node Name、Node Address、Endpoint、普通短 hex。
        let useful =
            redact_line("node mini 10.44.0.2 path=direct endpoint=203.0.113.9:41001 txid 1a2b3c");
        assert!(useful.contains("mini"), "{useful}");
        assert!(useful.contains("10.44.0.2"), "{useful}");
        assert!(useful.contains("203.0.113.9:41001"), "{useful}");
        assert!(useful.contains("1a2b3c"), "{useful}");

        // 普通文本里的 `hznet.` 前缀词不受误伤。
        let benign = redact_line("connecting to hznet.coord.example.com for hznet.example");
        assert_eq!(
            benign,
            "connecting to hznet.coord.example.com for hznet.example"
        );
    }

    #[test]
    fn tail_takes_last_n_lines_and_truncates() {
        let text: String = (0..2100).map(|n| format!("line {n}\n")).collect();
        let tail = tail_lines(&text, LOG_TAIL_LINES);
        assert_eq!(tail.len(), LOG_TAIL_LINES);
        assert_eq!(tail.first().unwrap(), "line 100");
        assert_eq!(tail.last().unwrap(), "line 2099");

        let long = "x".repeat(MAX_LINE_CHARS + 100);
        let truncated = truncate_line(&long);
        assert!(truncated.chars().count() <= MAX_LINE_CHARS + 10);
        assert!(truncated.ends_with("…(截断)"));
    }

    #[test]
    fn missing_log_file_yields_empty_tail_with_note() {
        // 文件不存在：空 tail + 说明，不报错（规格 §3.4）。
        let (tail, note) = collect_log_tail_from(Some(std::path::Path::new(
            "/nonexistent/hzd-diagnostic-test.log",
        )));
        assert!(tail.is_empty());
        let note = note.expect("应附说明");
        assert!(
            note.contains("不可读") || note.contains("log_tail 为空"),
            "{note}"
        );

        // 空文件：空 tail，说明仍带路径。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.log");
        std::fs::write(&path, "").unwrap();
        let (tail, note) = collect_log_tail_from(Some(&path));
        assert!(tail.is_empty());
        assert!(note.unwrap().contains("已脱敏"));
    }
}
