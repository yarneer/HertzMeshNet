//! `hz` 与 `hzd` 之间的本地 UDS 协议：每行一个 JSON 对象。
//! 请求 `{"id":n,"method":"status","params":{}}`，响应 `{"id":n,"result":{...}}` 或 `{"id":n,"error":"..."}`；
//! 服务端逐行读到 EOF。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// 单次请求整体限时，保证 hzd 卡死时 `hz` 快速失败而不是挂起。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    pub params: Value,
}

impl Request {
    pub fn new(id: u64, method: &str, params: Value) -> Self {
        Self {
            id,
            method: method.to_owned(),
            params,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Ok { id: u64, result: Value },
    Error { id: u64, error: String },
}

pub type Handler = Arc<dyn Fn(Request) -> Result<Value, String> + Send + Sync>;

pub async fn serve(socket_path: &Path, handler: Handler) -> anyhow::Result<()> {
    // hzd 崩溃后残留的 socket 文件会卡住重新绑定；单实例守护进程直接删除重绑。
    if socket_path.exists() {
        std::fs::remove_file(socket_path)
            .with_context(|| format!("failed to remove stale socket {}", socket_path.display()))?;
    }
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("failed to bind {}", socket_path.display()))?;
    let _guard = SocketGuard {
        path: socket_path.to_path_buf(),
    };
    tracing::info!(socket = %socket_path.display(), "ipc server listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let handler = handler.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, handler).await {
                tracing::warn!(%error, "ipc connection ended with error");
            }
        });
    }
}

/// serve 的 future 被取消（tokio abort）时也会走 Drop，保证 socket 文件不残留。
struct SocketGuard {
    path: PathBuf,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn handle_connection(stream: UnixStream, handler: Handler) -> anyhow::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        if line.trim().is_empty() {
            continue;
        }
        let request: Request = serde_json::from_str(line.trim())
            .map_err(|error| anyhow!("malformed ipc request: {error}"))?;
        let response = match handler(request.clone()) {
            Ok(result) => Response::Ok {
                id: request.id,
                result,
            },
            Err(error) => Response::Error {
                id: request.id,
                error,
            },
        };
        let mut payload = serde_json::to_string(&response)?;
        payload.push('\n');
        reader.get_mut().write_all(payload.as_bytes()).await?;
    }
}

pub async fn request(socket_path: &Path, request: Request) -> anyhow::Result<Response> {
    tokio::time::timeout(REQUEST_TIMEOUT, request_inner(socket_path, request))
        .await
        .map_err(|_| anyhow!("hzd did not respond within {}s", REQUEST_TIMEOUT.as_secs()))?
}

async fn request_inner(socket_path: &Path, request: Request) -> anyhow::Result<Response> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connect to {} failed", socket_path.display()))?;
    let mut reader = BufReader::new(stream);
    let mut payload = serde_json::to_string(&request)?;
    payload.push('\n');
    reader.get_mut().write_all(payload.as_bytes()).await?;

    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        bail!("hzd closed the connection without a response");
    }
    Ok(serde_json::from_str(line.trim())?)
}
