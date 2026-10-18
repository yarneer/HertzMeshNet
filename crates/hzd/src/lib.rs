//! hzd 守护进程主体：状态目录、密钥、UDS 服务与注册。
//! main 只负责 tracing 初始化与 Ctrl-C；守护化（systemd/launchd 托管）不在本进程内做。
//! 注册结果持久化在状态目录的 registration.json（0600），重启后仍是 Registered。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hz_core::coord_client::{DEFAULT_COORD_ADDR, local_hostname, register_with_auth_key};
use hz_core::ipc::{self, Handler};
use hz_core::keys::KeyStore;
use hz_core::status::{NodeStatus, RegisteredInfo};
use serde_json::Value;

const REGISTRATION_FILE: &str = "registration.json";

pub async fn run(state_dir: PathBuf, socket_path: PathBuf) -> anyhow::Result<()> {
    let keys = Arc::new(KeyStore::load_or_create(&state_dir)?);
    tracing::info!(
        machine_public = %hex(&keys.machine_public()),
        node_public = %hex(&keys.node_public()),
        "keys ready"
    );
    let registration = load_registration(&state_dir)?;
    if registration.is_some() {
        tracing::info!("loaded existing registration from disk");
    }
    let state = Arc::new(std::sync::Mutex::new(registration));
    let handler: Handler = {
        let state_dir = state_dir.clone();
        let state = state.clone();
        Arc::new(move |request: ipc::Request| {
            let state_dir = state_dir.clone();
            let state = state.clone();
            Box::pin(handle_request(request, state_dir, state))
        })
    };
    ipc::serve(&socket_path, handler).await
}

async fn handle_request(
    request: ipc::Request,
    state_dir: PathBuf,
    state: Arc<std::sync::Mutex<Option<RegisteredInfo>>>,
) -> Result<Value, String> {
    match request.method.as_str() {
        "status" => {
            let status = match state.lock().expect("registration state poisoned").clone() {
                Some(info) => NodeStatus::Registered(info),
                None => NodeStatus::Unregistered,
            };
            serde_json::to_value(status).map_err(|e| e.to_string())
        }
        "up" => {
            let auth_key = request
                .params
                .get("auth_key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "缺少 auth_key 参数".to_string())?
                .to_string();
            let coord_addr = request
                .params
                .get("coord_addr")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
                .or_else(|| std::env::var("HZD_COORD_ADDR").ok())
                .unwrap_or_else(|| DEFAULT_COORD_ADDR.to_string());

            let info =
                register_with_auth_key(&state_dir, &auth_key, &local_hostname(), &coord_addr)
                    .await
                    .map_err(|error| format!("{error:#}"))?;
            save_registration(&state_dir, &info).map_err(|error| format!("{error:#}"))?;
            *state.lock().expect("registration state poisoned") = Some(info.clone());
            tracing::info!(node_id = %info.node_id, name = %info.name, "node registered");
            serde_json::to_value(info).map_err(|e| e.to_string())
        }
        _ => Err(format!("unknown method: {}", request.method)),
    }
}

fn load_registration(state_dir: &Path) -> anyhow::Result<Option<RegisteredInfo>> {
    let path = state_dir.join(REGISTRATION_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).map_err(|error| anyhow::anyhow!("读取 {path:?} 失败：{error}"));
        }
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("{path:?} 内容损坏：{error}"))
}

fn save_registration(state_dir: &Path, info: &RegisteredInfo) -> anyhow::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let path = state_dir.join(REGISTRATION_FILE);
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(serde_json::to_string_pretty(info)?.as_bytes())?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
