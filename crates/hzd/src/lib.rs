//! hzd 守护进程主体：状态目录、密钥、UDS 服务。main 只负责 tracing 初始化与 Ctrl-C；
//! 守护化（systemd/launchd 托管）不在本进程内做。

use std::path::PathBuf;
use std::sync::Arc;

use hz_core::ipc::{self, Handler};
use hz_core::keys::KeyStore;
use hz_core::status::NodeStatus;
use serde_json::Value;

/// 入参按值持有 PathBuf：run 的 future 要能被 tokio::spawn，必须满足 'static。
pub async fn run(state_dir: PathBuf, socket_path: PathBuf) -> anyhow::Result<()> {
    let keys = KeyStore::load_or_create(&state_dir)?;
    tracing::info!(
        machine_public = %hex(&keys.machine_public()),
        node_public = %hex(&keys.node_public()),
        "keys ready"
    );
    let handler: Handler = Arc::new(handle_request);
    ipc::serve(&socket_path, handler).await
}

/// 注册流程尚未接入，状态一律是 Unregistered；票据 #3/#5 落地后由本地注册记录决定。
fn handle_request(request: ipc::Request) -> Result<Value, String> {
    match request.method.as_str() {
        "status" => serde_json::to_value(NodeStatus::Unregistered).map_err(|e| e.to_string()),
        _ => Err(format!("unknown method: {}", request.method)),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
