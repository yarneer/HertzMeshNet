//! `hz` 与 `hzd` 之间的本地 UDS 协议：每行一个 JSON 对象。
//! 请求 `{"id":n,"method":"status","params":{}}`，响应 `{"id":n,"result":{...}}` 或 `{"id":n,"error":"..."}`；
//! 服务端逐行读到 EOF。Handler 是异步的：注册这类要做网络 I/O 的方法不能阻塞连接循环。
//! 单行请求/响应均限制在 1 MiB，超限直接断言错误，防止失控输入耗尽内存。

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// 单次请求整体限时，保证 hzd 卡死时 `hz` 快速失败而不是挂起。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// 单行 JSON 上限（请求与响应双向）。
const MAX_LINE_BYTES: usize = 1024 * 1024;

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

type HandlerFuture = Pin<Box<dyn Future<Output = Result<Value, String>> + Send>>;

pub type Handler = Arc<dyn Fn(Request) -> HandlerFuture + Send + Sync>;

/// 把 async 闭包包成 Handler 的助手。
pub fn handler<F, Fut>(f: F) -> Handler
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Value, String>> + Send + 'static,
{
    Arc::new(move |request| Box::pin(f(request)))
}

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
        if read_line_capped(&mut reader, &mut line).await? == 0 {
            return Ok(());
        }
        if line.trim().is_empty() {
            continue;
        }
        let request: Request = serde_json::from_str(line.trim())
            .map_err(|error| anyhow!("malformed ipc request: {error}"))?;
        let id = request.id;
        let response = match handler(request).await {
            Ok(result) => Response::Ok { id, result },
            Err(error) => Response::Error { id, error },
        };
        let mut payload = serde_json::to_string(&response)?;
        payload.push('\n');
        reader.get_mut().write_all(payload.as_bytes()).await?;
    }
}

/// read_line 的限长版：超过 [`MAX_LINE_BYTES`] 报错而不是无限吞内存。
async fn read_line_capped<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    buf: &mut String,
) -> anyhow::Result<usize> {
    let mut total = 0usize;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(total);
        }
        let mut chunk_len = available.len();
        let newline_at = available.iter().position(|&b| b == b'\n');
        if let Some(pos) = newline_at {
            chunk_len = pos + 1;
        }
        if total + chunk_len > MAX_LINE_BYTES {
            bail!("ipc line exceeds {MAX_LINE_BYTES} bytes");
        }
        let chunk = std::str::from_utf8(&available[..chunk_len])
            .map_err(|error| anyhow!("ipc line is not valid UTF-8: {error}"))?;
        buf.push_str(chunk);
        total += chunk_len;
        reader.consume(chunk_len);
        if newline_at.is_some() {
            return Ok(total);
        }
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
    if read_line_capped(&mut reader, &mut line).await? == 0 {
        bail!("hzd closed the connection without a response");
    }
    Ok(serde_json::from_str(line.trim())?)
}
