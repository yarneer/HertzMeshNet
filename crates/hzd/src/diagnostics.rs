//! 脱敏诊断导出（#84 / MC-4）：`hz diagnostics` 与 macOS Client App 的
//! 「导出诊断包」共用的 IPC 数据在这里组装。
//!
//! `log_tail` 为 hzd 日志最近 [`LOG_TAIL_LINES`] 行——日志文件普通用户未必
//! 可读，由 hzd（通常以 root 运行）代读。读不到（文件不存在 / 不可读 /
//! 非 systemd 环境）时为空并附说明，不报错。
//!
//! 脱敏（`redact_secrets`，纯函数）：去掉私钥、Auth Key、邀请码、登录 URL
//! 中的 token，以及 Bearer / JWT / Cookie / Authorization 凭证；保留 Node
//! Name、Node Address 与 Endpoint（排障需要）。`log_tail` 逐行脱敏之后，
//! 整份诊断 JSON 再跑同一套规则（#108）。

use std::path::PathBuf;

use serde_json::Value;

/// 诊断包里日志的最大行数。
pub const LOG_TAIL_LINES: usize = 2000;

/// 单行截断上限：tracing 正常行远短于此，防个别爆行撑爆 IPC 1 MiB 上限。
const MAX_LINE_CHARS: usize = 8 * 1024;

/// log_tail 总量预算（#84 评审）：2000 行 × 8 KiB 最坏可超 IPC 单行 1 MiB
/// 上限——超预算时从最老的行开始丢弃，而不是让整份诊断以传输错误失败。
/// 预算给 status/netcheck 部分留了充足余量。
const MAX_TAIL_BYTES: usize = 512 * 1024;

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
                let lines = fit_tail_budget(redact_lines(tail_lines(&text, LOG_TAIL_LINES)));
                let count = lines.len();
                (
                    lines,
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

/// 一行日志的脱敏（#84 / #108：私钥 / Auth Key / 邀请码 / 登录 token /
/// Bearer / JWT / Cookie / Authorization 不出现，Node Name / Node Address /
/// Endpoint 保留）。含 `PRIVATE KEY` 的行整行替换——PEM 块的同行上下文没有
/// 排障价值。整包 JSON 不能走这条短路，见 [`redact_package`]。
pub fn redact_line(line: &str) -> String {
    if line.contains("PRIVATE KEY") {
        return format!("…{REDACTED}（PEM 私钥块）");
    }
    redact_secrets(line)
}

/// token 级规则，`redact_line` 与整包二次脱敏共用。按序：
///
/// 1. Auth Key / Relay Token：`hznet.` / `hzrelay.` 后的 base64url 主体；
/// 2. 邀请码：`HZ-XXXX-XXXX`；
/// 3. 登录 URL：`/oidc/start/<login_id>` 与 `login_id=<…>`，同一行全部出现；
/// 4. `Authorization` 头、独立 `Bearer`、`Cookie` / `Set-Cookie`、裸 JWT；
/// 5. 私钥的 hex 形态：连续 ≥64 个十六进制字符（公钥同样命中，多脱不错）。
fn redact_secrets(text: &str) -> String {
    let mut text = redact_prefixed_secret(text, "hznet.");
    text = redact_prefixed_secret(&text, "hzrelay.");
    text = redact_invite_codes(&text);
    text = redact_login_tokens(&text);
    text = redact_authorization(&text);
    text = redact_bearer(&text);
    text = redact_cookies(&text);
    text = redact_jwts(&text);
    redact_long_hex(&text)
}

/// 整包纵深（#108）。`log_tail` 已经逐行脱敏；这里把 status / netcheck /
/// log_note 里将来漏进来的密钥再过同一套 token 规则。PEM 在整包里只替换
/// 块本身——`redact_line` 的整行短路会毁掉 JSON。
pub(crate) fn redact_package(value: Value) -> Value {
    let Ok(raw) = serde_json::to_string(&value) else {
        return value;
    };
    let scrubbed = redact_secrets(&redact_pem_inline(&raw));
    serde_json::from_str(&scrubbed).unwrap_or(value)
}

/// `-----BEGIN … PRIVATE KEY-----` … `-----END …-----` 整段替换，其余字节不动。
fn redact_pem_inline(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(begin) = rest.find("-----BEGIN") {
        if let Some(end) = pem_block_end(&rest[begin..]) {
            out.push_str(&rest[..begin]);
            out.push_str(REDACTED);
            rest = &rest[begin + end..];
        } else {
            out.push_str(&rest[..begin + "-----BEGIN".len()]);
            rest = &rest[begin + "-----BEGIN".len()..];
        }
    }
    out.push_str(rest);
    out
}

/// `after` 以 `-----BEGIN` 开头。返回块的字节长度（含 END 行），不是私钥块则 None。
fn pem_block_end(after: &str) -> Option<usize> {
    let end_rel = after.find("-----END")?;
    if !after[..end_rel].contains("PRIVATE KEY") {
        return None;
    }
    let tail = &after[end_rel + 5..];
    let close = tail.find("-----")?;
    Some(end_rel + 5 + close + 5)
}

/// 多行 PEM 私钥块的状态机脱敏（#84 评审）：BEGIN 行进入块内状态，直到
/// END 行——块内每行（64 字符 base64 体，无前缀，单行规则命中不了）整行
/// 替换。单行含 BEGIN 与 END 时不进入块内状态。
pub fn redact_lines(lines: Vec<String>) -> Vec<String> {
    let mut in_pem = false;
    lines
        .into_iter()
        .map(|line| {
            if in_pem {
                if line.contains("END") && line.contains("KEY") {
                    in_pem = false;
                }
                return REDACTED.to_string();
            }
            if line.contains("PRIVATE KEY") {
                in_pem = !line.contains("END");
                return format!("…{REDACTED}（PEM 私钥块）");
            }
            redact_line(&line)
        })
        .collect()
}

/// 总量超预算时从最老的行开始丢弃（保最近的日志，排障价值最高）。
fn fit_tail_budget(mut lines: Vec<String>) -> Vec<String> {
    let size = |lines: &Vec<String>| lines.iter().map(|l| l.len() + 2).sum::<usize>();
    while size(&lines) > MAX_TAIL_BYTES && lines.len() > 1 {
        lines.remove(0);
    }
    lines
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

/// 把 marker 之后的 token 段（到下一个非 URL/标识符字符）全部替换为 [REDACTED]。
fn redact_after_marker(line: &str, marker: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(found) = rest.find(marker) {
        let after = found + marker.len();
        out.push_str(&rest[..after]);
        let tail = &rest[after..];
        let token_len = tail
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.'))
            .count();
        rest = if token_len == 0 {
            tail
        } else {
            out.push_str(REDACTED);
            &tail[token_len..]
        };
    }
    out.push_str(rest);
    out
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

/// 短于这个长度的 Bearer / Authorization 凭证不当密钥（避开普通英文单词）。
const MIN_SECRET: usize = 8;

/// `Authorization:` / `Authorization=` 后的 `scheme token` 或裸 token。
fn redact_authorization(text: &str) -> String {
    redact_word_value(text, "authorization", |bytes, after_word| {
        let value = header_value_start(bytes, after_word)?;
        authorization_credential_end(bytes, value).map(|end| (value, end))
    })
}

/// 独立的 `Bearer <token>`（`Authorization: Bearer` 已由上面的规则吃掉）。
fn redact_bearer(text: &str) -> String {
    redact_word_value(text, "bearer", |bytes, after_word| {
        let mut k = after_word;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k == after_word {
            return None;
        }
        let end = token_end(bytes, k);
        if end - k >= MIN_SECRET && !is_ipv4(&bytes[k..end]) {
            Some((k, end))
        } else {
            None
        }
    })
}

/// `Cookie:` / `Set-Cookie:` / `cookie=` 的值（`;` 分隔的多对一起换掉）。
fn redact_cookies(text: &str) -> String {
    redact_word_value(text, "cookie", |bytes, after_word| {
        let value = header_value_start(bytes, after_word)?;
        let end = cookie_value_end(bytes, value);
        (end > value).then_some((value, end))
    })
}

/// 在 `word`（大小写不敏感、两侧不是字母数字）之后按 `span` 替换凭证。
/// `span` 返回要替换的 `[start, end)`；None 表示这个出现不是凭证。
fn redact_word_value(
    text: &str,
    word: &str,
    mut span: impl FnMut(&[u8], usize) -> Option<(usize, usize)>,
) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some((_, after)) = next_word(text, i, word) {
        if let Some((start, end)) = span(bytes, after) {
            out.push_str(&text[i..start]);
            out.push_str(REDACTED);
            i = end;
        } else {
            out.push_str(&text[i..after]);
            i = after;
        }
    }
    out.push_str(&text[i..]);
    out
}

/// 词后有空白，再是 `:` 或 `=`，再是空白，返回值的起点。
fn header_value_start(bytes: &[u8], after_word: usize) -> Option<usize> {
    let mut j = after_word;
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    if j >= bytes.len() || (bytes[j] != b':' && bytes[j] != b'=') {
        return None;
    }
    j += 1;
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    Some(j)
}

fn authorization_credential_end(bytes: &[u8], j: usize) -> Option<usize> {
    if j >= bytes.len() {
        return None;
    }
    let word_end = j + bytes[j..]
        .iter()
        .take_while(|b| b.is_ascii_alphabetic())
        .count();
    if word_end > j {
        let word = &bytes[j..word_end];
        const SCHEMES: [&[u8]; 5] = [b"bearer", b"basic", b"digest", b"negotiate", b"token"];
        if SCHEMES
            .iter()
            .any(|scheme| word.eq_ignore_ascii_case(scheme))
        {
            let mut k = word_end;
            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            let end = token_end(bytes, k);
            if end - k >= MIN_SECRET && !is_ipv4(&bytes[k..end]) {
                return Some(end);
            }
            return None;
        }
    }
    let end = token_end(bytes, j);
    if end - j >= MIN_SECRET && !is_ipv4(&bytes[j..end]) {
        Some(end)
    } else {
        None
    }
}

fn cookie_value_end(bytes: &[u8], mut j: usize) -> usize {
    let start = j;
    loop {
        let pair = j;
        while j < bytes.len() && is_cookie_octet(bytes[j]) {
            j += 1;
        }
        if j == pair {
            return if pair == start { start } else { j };
        }
        if j < bytes.len() && bytes[j] == b';' {
            let mut k = j + 1;
            while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
                k += 1;
            }
            if k < bytes.len() && is_cookie_octet(bytes[k]) {
                j = k;
                continue;
            }
        }
        return j;
    }
}

/// ponytail: 停在 `"` 与 `\` 前，整包 JSON 才还能解析；带引号的 cookie 值要再加引号状态机。
fn is_cookie_octet(b: u8) -> bool {
    !b.is_ascii_whitespace() && b != b';' && b != b'"' && b != b'\\'
}

fn redact_jwts(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(rel) = text[i..].find("eyJ") {
        let at = i + rel;
        // `=` / `.` 是边界：`id_token=eyJ…` 与 URL 里的 JWT 都要脱。字母数字与 `-_` 才算嵌在别的 token 里。
        let inside_token = at > 0
            && (bytes[at - 1].is_ascii_alphanumeric()
                || bytes[at - 1] == b'-'
                || bytes[at - 1] == b'_');
        if let Some(len) = (!inside_token).then(|| jwt_len(&text[at..])).flatten() {
            out.push_str(&text[i..at]);
            out.push_str(REDACTED);
            i = at + len;
        } else {
            out.push_str(&text[i..at + 3]);
            i = at + 3;
        }
    }
    out.push_str(&text[i..]);
    out
}

/// 三段 base64url（每段 ≥10）以 `.` 分隔。返回字节长度。
fn jwt_len(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut pos = 0;
    for segment in 0..3 {
        let start = pos;
        while pos < bytes.len() && is_b64url(bytes[pos]) {
            pos += 1;
        }
        if pos - start < 10 {
            return None;
        }
        if segment < 2 {
            if pos >= bytes.len() || bytes[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }
    Some(pos)
}

fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'=')
}

fn token_end(bytes: &[u8], start: usize) -> usize {
    let mut j = start;
    while j < bytes.len() && is_secret_char(bytes[j]) {
        j += 1;
    }
    j
}

fn is_secret_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+' | b'/' | b'=')
}

fn is_ipv4(token: &[u8]) -> bool {
    std::str::from_utf8(token)
        .ok()
        .and_then(|text| text.parse::<std::net::Ipv4Addr>().ok())
        .is_some()
}

fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let needle = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

fn next_word(text: &str, start: usize, word: &str) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut from = start;
    while from < bytes.len() {
        let rel = find_ci(&text[from..], word)?;
        let at = from + rel;
        let end = at + word.len();
        let left_ok = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
        let right_ok = end >= bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if left_ok && right_ok {
            return Some((at, end));
        }
        from = end;
    }
    None
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
    fn repeated_markers_and_generic_secrets_are_redacted() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let line = format!(
            "node mini 10.44.0.2 endpoint=203.0.113.9:41001 \
             /oidc/start/n-aaaaaaaaaaaaaaaa /oidc/start/n-bbbbbbbbbbbbbbbb \
             login_id=n-cccccccccccccccc login_id=n-dddddddddddddddd \
             Bearer sk_live_51Habcdefghijklmnopqrstuv bEaReR sk_live_51Hzzzzzzzzzzzzzzzzzzzz \
             AUTHORIZATION: Basic dXNlcjpwYXNzdzByZA== \
             Set-Cookie: hz_admin=s3cr3tc00k13value; Path=/admin id_token={jwt} \
             endpoint=198.51.100.8:41001 Bearer 203.0.113.10:41002"
        );
        let redacted = redact_line(&line);
        for secret in [
            "n-aaaaaaaaaaaaaaaa",
            "n-bbbbbbbbbbbbbbbb",
            "n-cccccccccccccccc",
            "n-dddddddddddddddd",
            "sk_live_51Habcdefghijklmnopqrstuv",
            "sk_live_51Hzzzzzzzzzzzzzzzzzzzz",
            "dXNlcjpwYXNzdzByZA==",
            "s3cr3tc00k13value",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ] {
            assert!(!redacted.contains(secret), "{secret} still in {redacted}");
        }
        assert!(redacted.contains("mini"), "{redacted}");
        assert!(redacted.contains("10.44.0.2"), "{redacted}");
        assert!(redacted.contains("203.0.113.9:41001"), "{redacted}");
        assert!(redacted.contains("198.51.100.8:41001"), "{redacted}");
        assert!(redacted.contains("203.0.113.10:41002"), "{redacted}");
        assert_eq!(
            redacted.matches("/oidc/start/[REDACTED]").count(),
            2,
            "{redacted}"
        );
        assert_eq!(
            redacted.matches("login_id=[REDACTED]").count(),
            2,
            "{redacted}"
        );
    }

    #[test]
    fn package_redacts_secrets_that_missed_the_log_tail() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let value = serde_json::json!({
            "status": {
                "name": "mini",
                "ipv4": "10.44.0.2",
                "note": format!(
                    "leaked hznet.c3VwZXJzZWNyZXRrZXlkb25vdGNoYXJlMTIz Authorization: Bearer {jwt} Cookie: hz_admin=s3cr3tc00k13value -----BEGIN PRIVATE KEY----- MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6 -----END PRIVATE KEY-----"
                ),
            },
            "netcheck": {"endpoints": [{"addr": "203.0.113.9:41001"}]},
            "log_tail": ["node mini endpoint=203.0.113.9:41001"],
        });
        let redacted = redact_package(value);
        let whole = serde_json::to_string(&redacted).unwrap();
        assert!(
            !whole.contains("c3VwZXJzZWNyZXRrZXlkb25vdGNoYXJl"),
            "{whole}"
        );
        assert!(
            !whole.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
            "{whole}"
        );
        assert!(!whole.contains("s3cr3tc00k13value"), "{whole}");
        assert!(
            !whole.contains("MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6"),
            "{whole}"
        );
        assert!(whole.contains("mini"), "{whole}");
        assert!(whole.contains("10.44.0.2"), "{whole}");
        assert!(whole.contains("203.0.113.9:41001"), "{whole}");
        assert_eq!(redacted["status"]["name"], "mini");
        assert_eq!(
            redacted["log_tail"][0],
            "node mini endpoint=203.0.113.9:41001"
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
    fn multiline_pem_body_lines_are_redacted_as_a_block() {
        let lines = vec![
            "before".to_string(),
            "-----BEGIN PRIVATE KEY-----".to_string(),
            "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA".to_string(),
            "morebase64bodyline==".to_string(),
            "-----END PRIVATE KEY-----".to_string(),
            "after".to_string(),
        ];
        let redacted = redact_lines(lines);
        assert!(
            !redacted.iter().any(|l| l.contains("MIIBVAIB")),
            "{redacted:?}"
        );
        assert!(
            !redacted.iter().any(|l| l.contains("morebase64")),
            "{redacted:?}"
        );
        assert_eq!(redacted[0], "before");
        assert_eq!(redacted[5], "after");
    }

    #[test]
    fn tail_budget_drops_oldest_lines_first() {
        let lines: Vec<String> = (0..100)
            .map(|i| format!("log-{i:03} {}", "x".repeat(6000)))
            .collect();
        let fitted = fit_tail_budget(lines);
        // 100 × ~6KB = 600KB > 512KB 预算 → 丢弃最老行。
        assert!(fitted.len() < 100);
        assert!(fitted.last().unwrap().starts_with("log-099"), "最新行保留");
        let total: usize = fitted.iter().map(|l| l.len() + 2).sum();
        assert!(total <= MAX_TAIL_BYTES || fitted.len() == 1);
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
