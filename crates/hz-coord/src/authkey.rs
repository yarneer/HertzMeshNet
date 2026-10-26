//! Auth Key（FR-1）：明文形如 `hznet.<base64url(32 bytes)>`，只在签发时返回一次，
//! 服务端只保存 sha256 哈希。

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

const PREFIX: &str = "hznet.";
const RELAY_PREFIX: &str = "hzrelay.";
const KEY_RANDOM_BYTES: usize = 32;

pub fn generate_plaintext() -> String {
    let mut bytes = [0u8; KEY_RANDOM_BYTES];
    OsRng.fill_bytes(&mut bytes);
    format!("{PREFIX}{}", B64URL.encode(bytes))
}

/// 邀请码（#55）：`HZ-XXXX-XXXX`，8 字符取自 32 位无歧义字母表（去
/// 0/O/1/I/L），约 40 bit 熵——可口头转述、可对抗配合限速的在线爆破。
const INVITE_PREFIX: &str = "HZ-";
const INVITE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

pub fn generate_invite_code() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    let body: String = bytes
        .iter()
        .map(|b| INVITE_ALPHABET[(*b as usize) % INVITE_ALPHABET.len()] as char)
        .collect();
    format!("{INVITE_PREFIX}{}-{}", &body[..4], &body[4..])
}

/// 规范化：去 HZ- 前缀、去连字符、大写——生成与校验共用同一形再哈希，
/// 用户输入大小写或连字符差异都能命中。
pub fn normalize_invite(code: &str) -> String {
    code.trim()
        .strip_prefix(INVITE_PREFIX)
        .unwrap_or(code.trim())
        .replace(['-', ' '], "")
        .replace('\t', "")
        .to_uppercase()
}

/// Relay 呈给 Coordination Server 的长启用期共享令牌；库里同样只存 sha256。
pub fn generate_relay_token() -> String {
    let mut bytes = [0u8; KEY_RANDOM_BYTES];
    OsRng.fill_bytes(&mut bytes);
    format!("{RELAY_PREFIX}{}", B64URL.encode(bytes))
}

pub fn hash(plaintext: &str) -> String {
    let digest = Sha256::digest(plaintext.as_bytes());
    hex(&digest)
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub fn random_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_shape_and_hash_stability() {
        let key = generate_plaintext();
        assert!(
            key.starts_with("hznet."),
            "Auth Key 明文应带 hznet. 前缀：{key}"
        );
        assert_eq!(key.len(), "hznet.".len() + 43); // base64url(32B) 无填充 = 43 字符
        assert_eq!(hash(&key), hash(&key));
        assert_ne!(hash(&key), hash("hznet.different"));
    }

    #[test]
    fn relay_token_shape_is_distinct_from_auth_keys() {
        let token = generate_relay_token();
        assert!(token.starts_with("hzrelay."));
        assert_eq!(token.len(), "hzrelay.".len() + 43);
        assert_ne!(hash(&token), hash(&generate_relay_token()));
    }
}
