//! 注册挑战缓存：内存中的一次性 nonce（TTL 5 分钟），不落库。
//! 挑战与 Hello 提供的 Machine Key 公钥和主机名绑定，Register 时取走即失效。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

pub const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);

/// Hello 随报的 Node 软件版本与平台（#71 / OB-1）。挂在挑战上：Hello 本身
/// 不认证身份（此时还没有签名），版本信息随挑战被认证 rpc 取走时才落库。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeRuntime {
    pub node_version: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub machine_key_pub: [u8; 32],
    pub hostname: String,
    pub runtime: NodeRuntime,
    pub expires: Instant,
}

#[derive(Default)]
pub struct ChallengeCache {
    inner: std::sync::Mutex<HashMap<[u8; 32], Challenge>>,
}

impl ChallengeCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn issue(
        &self,
        machine_key_pub: [u8; 32],
        hostname: String,
        runtime: NodeRuntime,
    ) -> ([u8; 32], Instant) {
        let expires = Instant::now() + CHALLENGE_TTL;
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let mut guard = self.inner.lock().expect("challenge cache poisoned");
        guard.retain(|_, challenge| challenge.expires > Instant::now());
        guard.insert(
            nonce,
            Challenge {
                machine_key_pub,
                hostname,
                runtime,
                expires,
            },
        );
        (nonce, expires)
    }

    /// 取走挑战：无论校验结果如何都一次性消费，防重放。
    pub fn take(&self, nonce: &[u8; 32]) -> Option<Challenge> {
        let mut guard = self.inner.lock().expect("challenge cache poisoned");
        guard.remove(nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_single_use() {
        let cache = ChallengeCache::new();
        let (nonce, _) = cache.issue([7u8; 32], "host".into(), NodeRuntime::default());
        assert!(cache.take(&nonce).is_some());
        assert!(cache.take(&nonce).is_none(), "挑战必须一次性消费");
    }

    #[test]
    fn issued_challenges_carry_their_hello_data() {
        let cache = ChallengeCache::new();
        let runtime = NodeRuntime {
            node_version: Some("0.3.0 (a1b2c3d)".to_string()),
            os: Some("macos".to_string()),
            arch: Some("aarch64".to_string()),
        };
        let (nonce, expires) = cache.issue([9u8; 32], "Host A".into(), runtime.clone());
        let challenge = cache.take(&nonce).unwrap();
        assert_eq!(challenge.machine_key_pub, [9u8; 32]);
        assert_eq!(challenge.hostname, "Host A");
        assert_eq!(challenge.runtime, runtime);
        assert!(expires > Instant::now());
    }
}
