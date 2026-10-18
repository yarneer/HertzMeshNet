//! 交互式登录的 PendingLogin 注册表（FR-2）：内存状态机，login_id 一次性。
//! 生命周期：Begin（挑战认证通过）→ 浏览器经 /oidc/start 打开 → OIDC 回调落定
//! → LoginStatus 轮询取走终态后移除。过期与重复使用都是可读的终态。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

use crate::store::NodeRecord;

/// 登录链接有效期；AC 只要求"短时间后过期"。
pub const LOGIN_TTL: Duration = Duration::from_secs(5 * 60);

/// 登录标识，URL 里的最后一段；由服务端生成，不透明字符串。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LoginId(pub String);

impl LoginId {
    fn generate() -> Self {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(crate::authkey::hex(&bytes))
    }
}

/// 登录的当前阶段；NotYet 与终态互斥，而不是布尔标志堆。
#[derive(Debug)]
enum Stage {
    /// 浏览器侧还没走完，等待回调。
    Waiting,
    /// 回调成功，Node 已绑定到 User。
    Completed(NodeRecord),
    /// 终态失败（链接复用、过期、IdP 拒绝）。
    Failed(String),
}

#[derive(Debug)]
struct PendingLogin {
    machine_key_pub: [u8; 32],
    hostname: String,
    node_key_pub: Vec<u8>,
    nonce: String,
    pkce_verifier: String,
    expires_at: Instant,
    stage: Stage,
}

impl PendingLogin {
    fn expired(&self) -> bool {
        self.expires_at <= Instant::now()
    }
}

/// 单机内存注册表；进程重启即清空（未完成的登录作废，Node 重新发起即可）。
#[derive(Default)]
pub struct LoginRegistry {
    inner: Mutex<HashMap<String, PendingLogin>>,
}

/// Begin 阶段拿到的结果：login_id 用于拼一次性 URL。
pub struct StartedLogin {
    pub login_id: LoginId,
}

/// /oidc/start 与 /oidc/callback 共用的取件结果。
#[derive(Debug)]
pub enum TakeError {
    NotFound,
    Expired,
    AlreadyUsed,
}

impl LoginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记一个新的待完成登录。同一 Machine Key 已有未落定的登录时拒绝，
    /// 避免同一台机器同时持有两条一次性链接造成困惑。
    pub fn begin(
        &self,
        machine_key_pub: [u8; 32],
        hostname: String,
        node_key_pub: Vec<u8>,
        nonce: String,
        pkce_verifier: String,
        ttl: Duration,
    ) -> Result<StartedLogin, &'static str> {
        let mut guard = self.inner.lock().expect("login registry poisoned");
        guard.retain(|_, pending| !pending.expired());
        if guard.values().any(|pending| {
            pending.machine_key_pub == machine_key_pub && matches!(pending.stage, Stage::Waiting)
        }) {
            return Err("已有一个未完成的登录链接，请完成它或等待其过期后重试");
        }
        let login_id = LoginId::generate();
        let expires_at = Instant::now() + ttl;
        guard.insert(
            login_id.0.clone(),
            PendingLogin {
                machine_key_pub,
                hostname,
                node_key_pub,
                nonce,
                pkce_verifier,
                expires_at,
                stage: Stage::Waiting,
            },
        );
        Ok(StartedLogin { login_id })
    }

    /// /oidc/start 取授权参数。已完成或已失败的登录不可再次开始授权。
    pub fn authorize_material(&self, login_id: &str) -> Result<(String, String), TakeError> {
        let guard = self.inner.lock().expect("login registry poisoned");
        let pending = guard.get(login_id).ok_or(TakeError::NotFound)?;
        if pending.expired() {
            return Err(TakeError::Expired);
        }
        match &pending.stage {
            Stage::Waiting => Ok((pending.nonce.clone(), pending.pkce_verifier.clone())),
            Stage::Completed(_) | Stage::Failed(_) => Err(TakeError::AlreadyUsed),
        }
    }

    /// 回调落定：校验 state 对应的登录仍处 Waiting，取出绑定材料并交回登记接口。
    /// 返回闭包写入的终态由 complete/abort 落地。
    pub fn take_for_callback(&self, login_id: &str) -> Result<CallbackMaterial, TakeError> {
        let mut guard = self.inner.lock().expect("login registry poisoned");
        let pending = guard.get_mut(login_id).ok_or(TakeError::NotFound)?;
        if pending.expired() {
            return Err(TakeError::Expired);
        }
        match pending.stage {
            Stage::Waiting => Ok(CallbackMaterial {
                machine_key_pub: pending.machine_key_pub,
                hostname: pending.hostname.clone(),
                node_key_pub: pending.node_key_pub.clone(),
                nonce: pending.nonce.clone(),
                pkce_verifier: pending.pkce_verifier.clone(),
            }),
            Stage::Completed(_) | Stage::Failed(_) => Err(TakeError::AlreadyUsed),
        }
    }

    /// 回调成功：落 Completed 终态，等待 Node 轮询取走。
    pub fn complete(&self, login_id: &str, record: NodeRecord) {
        let mut guard = self.inner.lock().expect("login registry poisoned");
        if let Some(pending) = guard.get_mut(login_id) {
            pending.stage = Stage::Completed(record);
        }
    }

    /// 回调失败：落 Failed 终态。
    pub fn fail(&self, login_id: &str, reason: String) {
        let mut guard = self.inner.lock().expect("login registry poisoned");
        if let Some(pending) = guard.get_mut(login_id) {
            pending.stage = Stage::Failed(reason);
        }
    }

    /// Node 轮询。终态只交付一次，交付后移除（链接一次性在轮询侧同样成立）。
    pub fn poll(&self, login_id: &str, machine_key_pub: &[u8; 32]) -> PollResult {
        let mut guard = self.inner.lock().expect("login registry poisoned");
        let Some(pending) = guard.get(login_id) else {
            return PollResult::Failed("登录链接不存在或已被使用，请重新发起登录".to_string());
        };
        if pending.machine_key_pub != *machine_key_pub {
            return PollResult::Failed("登录链接与该 Machine Key 不匹配".to_string());
        }
        if pending.expired() {
            guard.remove(login_id);
            return PollResult::Failed("登录链接已过期，请重新发起登录".to_string());
        }
        if matches!(pending.stage, Stage::Waiting) {
            return PollResult::Pending;
        }
        match guard.remove(login_id).expect("login just checked").stage {
            Stage::Completed(record) => PollResult::Completed(record),
            Stage::Failed(reason) => PollResult::Failed(reason),
            Stage::Waiting => unreachable!("waiting handled above"),
        }
    }
}

/// 回调处理需要的全部绑定材料。
pub struct CallbackMaterial {
    pub machine_key_pub: [u8; 32],
    pub hostname: String,
    pub node_key_pub: Vec<u8>,
    pub nonce: String,
    pub pkce_verifier: String,
}

#[derive(Debug)]
pub enum PollResult {
    Pending,
    Completed(NodeRecord),
    Failed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> ([u8; 32], String, Vec<u8>) {
        ([1u8; 32], "host-a".to_string(), vec![2u8; 32])
    }

    #[test]
    fn begin_rejects_second_pending_login_for_same_machine() {
        let registry = LoginRegistry::new();
        let (machine, hostname, node_key) = material();
        registry
            .begin(
                machine,
                hostname.clone(),
                node_key.clone(),
                "n".to_string(),
                "v".to_string(),
                LOGIN_TTL,
            )
            .unwrap();
        let rejected = registry.begin(
            machine,
            hostname,
            node_key,
            "n2".to_string(),
            "v2".to_string(),
            LOGIN_TTL,
        );
        assert!(rejected.is_err(), "同一机器不得同时持有两条待完成登录");
    }

    #[test]
    fn completed_login_is_single_use_across_start_and_poll() {
        let registry = LoginRegistry::new();
        let (machine, hostname, node_key) = material();
        let started = registry
            .begin(
                machine,
                hostname,
                node_key,
                "nonce".to_string(),
                "verifier".to_string(),
                LOGIN_TTL,
            )
            .unwrap();
        let id = started.login_id.0.clone();

        registry.authorize_material(&id).unwrap();
        let callback = registry.take_for_callback(&id).unwrap();
        assert_eq!(callback.nonce, "nonce");
        registry.complete(
            &id,
            NodeRecord {
                id: "node-1".to_string(),
                name: "host-a".to_string(),
                ipv4: "100.96.0.2".parse().unwrap(),
                ipv6: "fd00::2".parse().unwrap(),
                tags: vec![],
                owner_user: Some("alice".to_string()),
                expires_at_unix: Some(1),
                node_key_pub: vec![2u8; 32],
                udp_endpoints: vec![],
            },
        );

        assert!(matches!(
            registry.authorize_material(&id),
            Err(TakeError::AlreadyUsed)
        ));
        match registry.poll(&id, &machine) {
            PollResult::Completed(record) => {
                assert_eq!(record.owner_user.as_deref(), Some("alice"))
            }
            other => panic!("首次轮询应取回完成态：{other:?}"),
        }
        assert!(matches!(
            registry.poll(&id, &machine),
            PollResult::Failed(_)
        ));
    }

    #[test]
    fn expired_login_rejected_on_poll_and_removed() {
        let registry = LoginRegistry::new();
        let (machine, hostname, node_key) = material();
        let started = registry
            .begin(
                machine,
                hostname,
                node_key,
                "n".to_string(),
                "v".to_string(),
                Duration::from_millis(0),
            )
            .unwrap();
        let id = started.login_id.0.clone();
        match registry.poll(&id, &machine) {
            PollResult::Failed(reason) => assert!(reason.contains("过期"), "实际信息：{reason}"),
            other => panic!("过期登录应报错：{other:?}"),
        }
    }

    #[test]
    fn poll_binds_login_to_the_machine_that_began_it() {
        let registry = LoginRegistry::new();
        let (machine, hostname, node_key) = material();
        let started = registry
            .begin(
                machine,
                hostname,
                node_key,
                "n".to_string(),
                "v".to_string(),
                LOGIN_TTL,
            )
            .unwrap();
        match registry.poll(&started.login_id.0, &[9u8; 32]) {
            PollResult::Failed(reason) => assert!(reason.contains("Machine Key")),
            other => panic!("别的机器轮询应被拒绝：{other:?}"),
        }
    }
}
