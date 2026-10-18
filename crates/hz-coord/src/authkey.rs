//! Auth Key（FR-1）：明文形如 `hznet.<base64url(32 bytes)>`，只在签发时返回一次，
//! 服务端只保存 sha256 哈希。

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

const PREFIX: &str = "hznet.";
const KEY_RANDOM_BYTES: usize = 32;

pub fn generate_plaintext() -> String {
    let mut bytes = [0u8; KEY_RANDOM_BYTES];
    OsRng.fill_bytes(&mut bytes);
    format!("{PREFIX}{}", B64URL.encode(bytes))
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
}
