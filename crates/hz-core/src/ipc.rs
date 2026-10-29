//! `hz` 与 `hzd` 之间的本地 UDS 协议：每行一个 JSON 对象。
//! 请求 `{"id":n,"method":"status","params":{}}`，响应 `{"id":n,"result":{...}}` 或 `{"id":n,"error":"..."}`；
//! 服务端逐行读到 EOF。Handler 是异步的：注册这类要做网络 I/O 的方法不能阻塞连接循环。
//! 单行请求/响应均限制在 1 MiB，超限直接断言错误，防止失控输入耗尽内存。
//!
//! 一请求多响应（#95，`subscribe` 的前置）：除一问一答的 [`Handler`] 外，
//! 服务端还可注册流式方法——对同一请求 id 逐行推送多条 [`Response`]，直到
//! 流结束或客户端断开；客户端用 [`request_stream`] 逐行读取。流式方法不受
//! 单次请求 30 秒超时约束（那是 [`request`] 的客户端限时），一问一答方法
//! 行为完全不变。

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

/// 单次请求整体限时，保证 hzd 卡死时 `hz` 快速失败而不是挂起。
/// 只约束 [`request`]（一问一答）；流式方法走 [`request_stream`]，不设此限。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// 单行 JSON 上限（请求与响应双向，含流式响应的每一行）。
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

/// 流式方法：对同一请求 id 经 sender 逐行推送 [`Response`]，直到函数返回
/// （流结束）或客户端断开（后续 send 失败，应尽快返回以释放资源）。
type StreamFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

pub type StreamHandler =
    Arc<dyn Fn(Request, mpsc::Sender<Response>) -> StreamFuture + Send + Sync>;

/// 把 async 闭包包成 StreamHandler 的助手。
pub fn stream_handler<F, Fut>(f: F) -> StreamHandler
where
    F: Fn(Request, mpsc::Sender<Response>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    Arc::new(move |request, sender| Box::pin(f(request, sender)))
}

/// 已注册的流式方法表（方法名 → 处理函数）。
pub type Streams = Arc<HashMap<String, StreamHandler>>;

/// 只有单响应方法的 IPC 服务（现有一问一答语义，行为不变）。
pub async fn serve(socket_path: &Path, handler: Handler) -> anyhow::Result<()> {
    serve_with(socket_path, handler, Arc::new(HashMap::new())).await
}

/// 带流式方法的 IPC 服务：命中 `streams` 的方法名走一请求多响应，
/// 其余方法仍是一问一答。
pub async fn serve_with(
    socket_path: &Path,
    handler: Handler,
    streams: Streams,
) -> anyhow::Result<()> {
    // hzd 崩溃后残留的 socket 文件会卡住重新绑定；单实例守护进程直接删除重绑。
    if socket_path.exists() {
        std::fs::remove_file(socket_path)
            .with_context(|| format!("failed to remove stale socket {}", socket_path.display()))?;
    }
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("failed to bind {}", socket_path.display()))?;
    // 任何本机用户都能连上（只读查询不需要 sudo）；能做什么由 authorize
    // 按调用方 uid 判定，而不是靠文件权限一刀切。
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666))
            .with_context(|| format!("failed to chmod {}", socket_path.display()))?;
    }
    let _guard = SocketGuard {
        path: socket_path.to_path_buf(),
    };
    tracing::info!(socket = %socket_path.display(), "ipc server listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let handler = handler.clone();
        let streams = streams.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, handler, streams).await {
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

/// 任何本机用户都可发起的只读请求（#26）。其余请求以本 Node 的身份改动
/// 状态或读取 Policy、Node 列表等管理信息，只允许 root 或与 hzd 同一用户。
const READ_ONLY_METHODS: &[&str] = &["status", "ping", "netcheck"];

/// 按调用方 uid 判定能否执行 `method`：只读请求放行；其余要求调用方是
/// root 或与 hzd 同一用户（hzd 以普通用户运行的开发与测试场景）。
pub fn authorize(method: &str, peer_uid: u32, daemon_uid: u32) -> Result<(), String> {
    if READ_ONLY_METHODS.contains(&method) || peer_uid == 0 || peer_uid == daemon_uid {
        Ok(())
    } else {
        Err(format!("`{method}` 需要管理员权限，请用 sudo 执行"))
    }
}

async fn handle_connection(
    stream: UnixStream,
    handler: Handler,
    streams: Streams,
) -> anyhow::Result<()> {
    let peer_uid = stream.peer_cred()?.uid();
    // SAFETY: geteuid 无副作用、不会失败。
    let daemon_uid = unsafe { libc::geteuid() };
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
        if let Some(stream_handler) = streams.get(&request.method).cloned() {
            // 流式方法不受一问一答的生命周期约束：连接转给推送循环，本循环
            // 不再读取后续请求（一条流式连接只服务一个请求）。
            if let Err(error) = authorize(&request.method, peer_uid, daemon_uid) {
                let response = Response::Error { id, error };
                write_response_capped(reader.get_mut(), response).await?;
                return Ok(());
            }
            return stream_connection(reader, request, stream_handler).await;
        }
        let outcome = match authorize(&request.method, peer_uid, daemon_uid) {
            Ok(()) => handler(request).await,
            Err(error) => Err(error),
        };
        let response = match outcome {
            Ok(result) => Response::Ok { id, result },
            Err(error) => Response::Error { id, error },
        };
        write_response_capped(reader.get_mut(), response).await?;
    }
}

/// 流式请求的推送循环：handler 经 channel 逐行送响应，这里逐行写出；
/// 客户端断开（EOF）时丢弃 channel，让 handler 的后续 send 失败、尽快退出。
async fn stream_connection(
    reader: BufReader<UnixStream>,
    request: Request,
    stream_handler: StreamHandler,
) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;

    let stream = reader.into_inner();
    let (mut read_half, mut write_half) = stream.into_split();
    // EOF 哨兵：客户端断开时读半边立刻可感知（写侧要等缓冲排干才 EPIPE，
    // 流式心跳间隔下可能拖很久）。流式期间客户端发来的多余字节直接丢弃。
    let (eof_tx, eof_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut scratch = [0u8; 256];
        loop {
            match read_half.read(&mut scratch).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue,
            }
        }
        let _ = eof_tx.send(());
    });

    let (tx, mut rx) = mpsc::channel::<Response>(16);
    tokio::spawn(stream_handler(request, tx));
    let mut eof_rx = eof_rx;
    loop {
        tokio::select! {
            response = rx.recv() => {
                let Some(response) = response else {
                    // handler 正常返回：流结束，连接收尾。
                    break;
                };
                write_response_capped(&mut write_half, response).await?;
            }
            _ = &mut eof_rx => {
                // 客户端断开：drop receiver 使 handler 的下一次 send 失败。
                rx.close();
                break;
            }
        }
    }
    Ok(())
}

/// 序列化并写出一行响应；超过 [`MAX_LINE_BYTES`] 的行（含流式响应的每一行）
/// 直接报错断开连接，而不是把失控输出写给对端。
async fn write_response_capped<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: Response,
) -> anyhow::Result<()> {
    let payload = serde_json::to_string(&response)?;
    if payload.len() > MAX_LINE_BYTES {
        bail!("ipc response exceeds {MAX_LINE_BYTES} bytes");
    }
    let mut payload = payload;
    payload.push('\n');
    writer.write_all(payload.as_bytes()).await?;
    Ok(())
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

/// 打开一条流式请求：发送请求后返回逐行响应的接收端（一请求多响应，
/// #95）。不套 [`REQUEST_TIMEOUT`]——流可以长时间打开，消费节奏与空闲
/// 判定由调用方决定。连接建立/发送失败仍立即返回错误。
///
/// EOF、读到坏行或调用方 drop 接收端时，后台读取任务随之结束并关闭连接。
pub async fn request_stream(
    socket_path: &Path,
    request: Request,
) -> anyhow::Result<mpsc::Receiver<Response>> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connect to {} failed", socket_path.display()))?;
    let mut reader = BufReader::new(stream);
    let mut payload = serde_json::to_string(&request)?;
    payload.push('\n');
    reader.get_mut().write_all(payload.as_bytes()).await?;

    let (tx, rx) = mpsc::channel::<Response>(16);
    tokio::spawn(async move {
        let mut line = String::new();
        loop {
            line.clear();
            match read_line_capped(&mut reader, &mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            if line.trim().is_empty() {
                continue;
            }
            let Ok(response) = serde_json::from_str::<Response>(line.trim()) else {
                break;
            };
            if tx.send(response).await.is_err() {
                // 调用方不再消费：停止读取并关闭连接。
                break;
            }
        }
    });
    Ok(rx)
}
