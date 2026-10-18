//! 打洞信令（FR-8）：PunchOffer / PunchAck 封装在 Relay 的 RelayData 帧里
//! 转发，载荷用双方 Node Key 的 X25519 共享秘密派生 ChaCha20-Poly1305 密钥
//! 做端到端加密。Coordination Server 不接触这些帧，Relay 只见密文。
//! 帧前缀 b"HZP" 区别于 WireGuard 报文（WireGuard 首字节恒为 1..=4，
//! 第二字节恒为 0，与 H/Z 的 ASCII 码不冲突）。

use std::net::SocketAddr;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as NodePublicKey, StaticSecret as NodeStaticSecret};

/// 打洞帧明文前缀。
pub const MAGIC: [u8; 3] = *b"HZP";

/// AEAD 密钥派生标签：同一 X25519 秘密也喂养 WireGuard 会话，必须域分离。
const KEY_LABEL: &[u8] = b"hz-punch-aead-v1";
const NONCE_LEN: usize = 12;
/// Offer 携带的时间戳容差：Relay 通道转发可能滞后，超窗视为过期丢弃。
const TS_WINDOW_SECS: u64 = 60;

/// Relay 通道上的一个打洞信令。Offer 携带发送方的候选 Endpoint，
/// 接收方立即朝这些候选发 WireGuard 握手（同时打开双方 NAT）并回 Ack。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PunchMessage {
    Offer {
        nonce: [u8; 16],
        ts_unix: u64,
        candidates: Vec<SocketAddr>,
    },
    Ack {
        chosen: SocketAddr,
    },
}

/// 是否是打洞帧（Relay 入站数据报分流用）。
pub fn is_punch(datagram: &[u8]) -> bool {
    datagram.len() > MAGIC.len() + NONCE_LEN && datagram[..MAGIC.len()] == MAGIC
}

/// 一个对端的打洞编解码器：密钥 = SHA256(X25519(own, peer) || KEY_LABEL)。
pub struct PunchCodec {
    cipher: ChaCha20Poly1305,
}

impl PunchCodec {
    pub fn new(own_secret: &NodeStaticSecret, peer_node_key_pub: &[u8; 32]) -> Self {
        let shared = own_secret.diffie_hellman(&NodePublicKey::from(*peer_node_key_pub));
        let key = Sha256::new()
            .chain_update(shared.as_bytes())
            .chain_update(KEY_LABEL)
            .finalize();
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
        }
    }

    /// 编码 + 加密：MAGIC || nonce(12) || ciphertext。
    pub fn seal(&self, message: &PunchMessage) -> Vec<u8> {
        let plaintext = serde_json::to_vec(message).expect("punch message serializes");
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload::from(plaintext.as_slice()),
            )
            .expect("chacha20poly1305 encryption of in-memory data");
        let mut frame = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
        frame.extend_from_slice(&MAGIC);
        frame.extend_from_slice(&nonce_bytes);
        frame.extend_from_slice(&ciphertext);
        frame
    }

    /// 解密 + 解码。密钥不符、帧损坏、Offer 时间戳超窗都返回 None（静默丢弃，
    /// 不给伪造者反馈信道）。
    pub fn open(&self, frame: &[u8], now_unix: u64) -> Option<PunchMessage> {
        if !is_punch(frame) {
            return None;
        }
        let nonce = Nonce::from_slice(frame.get(MAGIC.len()..MAGIC.len() + NONCE_LEN)?);
        let ciphertext = frame.get(MAGIC.len() + NONCE_LEN..)?;
        let plaintext = self.cipher.decrypt(nonce, Payload::from(ciphertext)).ok()?;
        let message: PunchMessage = serde_json::from_slice(&plaintext).ok()?;
        if let PunchMessage::Offer { ts_unix, .. } = &message {
            if now_unix.abs_diff(*ts_unix) > TS_WINDOW_SECS {
                tracing::warn!(%ts_unix, now_unix, "punch offer outside time window, dropping");
                return None;
            }
        }
        Some(message)
    }
}

/// 供入站分流调用：帧当前时间的秒数（Relay 帧不带发送时钟，用本机时钟校验）。
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 用一对密钥把消息从 A 编到 B：A 用自己的私钥与 B 的公钥，B 反之。
/// 返回 (A 的 codec, B 的 codec)。
pub fn codec_pair(
    a_secret: &NodeStaticSecret,
    a_public: &[u8; 32],
    b_secret: &NodeStaticSecret,
    b_public: &[u8; 32],
) -> (PunchCodec, PunchCodec) {
    let _ = a_public;
    (
        PunchCodec::new(a_secret, b_public),
        PunchCodec::new(b_secret, a_public),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypairs() -> ((NodeStaticSecret, [u8; 32]), (NodeStaticSecret, [u8; 32])) {
        let a = NodeStaticSecret::random_from_rng(OsRng);
        let b = NodeStaticSecret::random_from_rng(OsRng);
        let ap = NodePublicKey::from(&a).to_bytes();
        let bp = NodePublicKey::from(&b).to_bytes();
        ((a, ap), (b, bp))
    }

    fn sample_offer() -> PunchMessage {
        PunchMessage::Offer {
            nonce: [7u8; 16],
            ts_unix: now_unix(),
            candidates: vec![
                "203.0.113.9:41001".parse().unwrap(),
                "[2001:db8::4]:51820".parse().unwrap(),
            ],
        }
    }

    #[test]
    fn offer_round_trips_between_peer_codecs() {
        let ((a_secret, a_public), (b_secret, b_public)) = keypairs();
        let (a, b) = codec_pair(&a_secret, &a_public, &b_secret, &b_public);
        let frame = a.seal(&sample_offer());
        assert!(is_punch(&frame));
        assert_eq!(b.open(&frame, now_unix()), Some(sample_offer()));
    }

    #[test]
    fn ack_round_trips() {
        let ((a_secret, a_public), (b_secret, b_public)) = keypairs();
        let (a, b) = codec_pair(&a_secret, &a_public, &b_secret, &b_public);
        let message = PunchMessage::Ack {
            chosen: "203.0.113.9:41001".parse().unwrap(),
        };
        let frame = a.seal(&message);
        assert_eq!(b.open(&frame, now_unix()), Some(message));
    }

    #[test]
    fn stranger_key_cannot_open() {
        let ((a_secret, a_public), (b_secret, b_public)) = keypairs();
        let intruder = NodeStaticSecret::random_from_rng(OsRng);
        let (a, _) = codec_pair(&a_secret, &a_public, &b_secret, &b_public);
        let wrong = PunchCodec::new(&intruder, &b_public);
        let frame = a.seal(&sample_offer());
        assert_eq!(wrong.open(&frame, now_unix()), None);
    }

    #[test]
    fn stale_offer_is_rejected() {
        let ((a_secret, a_public), (b_secret, b_public)) = keypairs();
        let (a, b) = codec_pair(&a_secret, &a_public, &b_secret, &b_public);
        let mut stale = sample_offer();
        if let PunchMessage::Offer { ts_unix, .. } = &mut stale {
            *ts_unix = now_unix().saturating_sub(3600);
        }
        let frame = a.seal(&stale);
        assert_eq!(b.open(&frame, now_unix()), None);
    }

    #[test]
    fn tampered_frame_fails_authentication() {
        let ((a_secret, a_public), (b_secret, b_public)) = keypairs();
        let (a, b) = codec_pair(&a_secret, &a_public, &b_secret, &b_public);
        let mut frame = a.seal(&sample_offer());
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        assert_eq!(b.open(&frame, now_unix()), None);
    }

    #[test]
    fn wireguard_datagrams_are_not_mistaken_for_punch() {
        assert!(!is_punch(&[1, 0, 0, 0, 1, 2, 3, 4]));
        assert!(!is_punch(b"HZ"));
        assert!(is_punch(&{
            let mut f = MAGIC.to_vec();
            f.extend(std::iter::repeat_n(0, 32));
            f
        }));
    }
}
