//! HTTP Admin API（`/admin/api`）与 Admin Console 的 OIDC 会话。
//!
//! 会话只发给 Kanidm `hznet_admins`（[`crate::oidc::UserClaims::is_admin`]，
//! 与 GLOSSARY 的 Admin 是同一件事）。没有第二套管理员口令。
//! Node / Auth Key / Policy / 健康 / 备份 REST 在 [`api_router`]，外层门禁
//! 已经挡住没有会话的请求。浏览器壳在 [`browser_entry`]（静态文件见
//! [`crate::admin_ui`]）：未登录走重定向，`/admin/api` 走 JSON 401。领域逻辑
//! 仍用 [`crate::admin`] 与 [`crate::store`] 里 gRPC Admin RPC 同一批函数，
//! 不在这里复制。v1 不提供 Auth Key 清单，也不提供 Policy 写入或任意 shell。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Extension, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::map_stream::MapHub;
use crate::metrics::Metrics;

use crate::http::HttpState;
use crate::login::LOGIN_TTL;
use crate::oidc::{self, UserClaims};

const COOKIE: &str = "hz_admin";
/// 浏览器会话寿命。只放内存，进程重启即失效，重新走 OIDC。
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

const UNAUTHENTICATED: &str = "unauthenticated";
const UNAUTHENTICATED_MESSAGE: &str = "需要 Admin 会话";
const NOT_FOUND: &str = "not_found";
const NOT_FOUND_MESSAGE: &str = "不存在";
/// 每日 cron 再留 12 小时余量。超过则健康页把备份标成不新鲜。
const BACKUP_FRESH_SECS: u64 = 36 * 60 * 60;
const CERT_NAMES: [&str; 3] = ["coord", "relay", "auth"];

/// 备份脚本、库文件、备份目录、证书目录。路径来自进程配置，不来自请求。
#[derive(Clone, Debug)]
pub struct OpsConfig {
    pub backup_script: PathBuf,
    pub db_path: Option<PathBuf>,
    pub backup_dir: PathBuf,
    pub tls_dir: PathBuf,
    /// 与 `healthcheck.sh --cert-days` 默认一致。
    pub cert_warn_days: u64,
    pub backup_timeout: Duration,
}

impl Default for OpsConfig {
    fn default() -> Self {
        Self {
            backup_script: PathBuf::from("scripts/deploy/backup.sh"),
            db_path: None,
            backup_dir: PathBuf::from("/var/backups/hznet"),
            tls_dir: PathBuf::from("/etc/hznet/tls"),
            cert_warn_days: 14,
            backup_timeout: Duration::from_secs(120),
        }
    }
}

/// 在线流、打洞计数、运维路径。备份锁是进程内的一把。
pub struct ConsoleState {
    pub hub: Option<Arc<MapHub>>,
    pub metrics: Option<Arc<Metrics>>,
    pub ops: OpsConfig,
    // ponytail: one backup at a time for this process. Per-host lock if coord is ever multi-process.
    backup_busy: AtomicBool,
}

impl ConsoleState {
    pub fn with_runtime(ops: OpsConfig, hub: Arc<MapHub>, metrics: Arc<Metrics>) -> Self {
        Self {
            hub: Some(hub),
            metrics: Some(metrics),
            ops,
            backup_busy: AtomicBool::new(false),
        }
    }

    fn try_backup(&self) -> Option<BackupGuard<'_>> {
        self.backup_busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| BackupGuard {
                flag: &self.backup_busy,
            })
    }
}

impl Default for ConsoleState {
    fn default() -> Self {
        Self {
            hub: None,
            metrics: None,
            ops: OpsConfig::default(),
            backup_busy: AtomicBool::new(false),
        }
    }
}

struct BackupGuard<'a> {
    flag: &'a AtomicBool,
}

impl Drop for BackupGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

/// 已登录的 Admin。后续 REST 处理函数拿 [`Extension<AdminSession>`]，
/// 操作者就是 `Operator::Admin { user: session.username }`。
#[derive(Clone, Debug)]
pub struct AdminSession {
    pub username: String,
    pub subject: String,
}

struct PendingAuth {
    nonce: String,
    verifier: String,
    expires_at: Instant,
}

struct LiveSession {
    username: String,
    subject: String,
    expires_at: Instant,
}

#[derive(Default)]
struct GateInner {
    pending: HashMap<String, PendingAuth>,
    sessions: HashMap<String, LiveSession>,
}

/// Admin OIDC 的一次性 state 与会话表。与 Node 的 PendingLogin 分开，
/// 回调不会去绑定 Node。
#[derive(Default)]
pub struct AdminGate {
    inner: Mutex<GateInner>,
}

impl AdminGate {
    fn lock(&self) -> std::sync::MutexGuard<'_, GateInner> {
        self.inner.lock().expect("admin gate poisoned")
    }

    fn begin(&self, state: String, nonce: String, verifier: String) {
        let mut guard = self.lock();
        let now = Instant::now();
        sweep(&mut guard, now);
        guard.pending.insert(
            state,
            PendingAuth {
                nonce,
                verifier,
                expires_at: now + LOGIN_TTL,
            },
        );
    }

    fn discard(&self, state: &str) {
        self.lock().pending.remove(state);
    }

    /// 一次性取走。过期与未知都是 None，避免区分这两种失败。
    fn take_pending(&self, state: &str) -> Option<(String, String)> {
        let mut guard = self.lock();
        sweep(&mut guard, Instant::now());
        guard
            .pending
            .remove(state)
            .map(|pending| (pending.nonce, pending.verifier))
    }

    fn open_session(&self, username: &str, subject: &str) -> String {
        let id = oidc::new_login_token("s");
        let mut guard = self.lock();
        sweep(&mut guard, Instant::now());
        guard.sessions.insert(
            id.clone(),
            LiveSession {
                username: username.to_owned(),
                subject: subject.to_owned(),
                expires_at: Instant::now() + SESSION_TTL,
            },
        );
        id
    }

    fn session(&self, id: &str) -> Option<AdminSession> {
        let mut guard = self.lock();
        sweep(&mut guard, Instant::now());
        guard.sessions.get(id).map(|session| AdminSession {
            username: session.username.clone(),
            subject: session.subject.clone(),
        })
    }
}

fn sweep(inner: &mut GateInner, now: Instant) {
    inner.pending.retain(|_, pending| pending.expires_at > now);
    inner.sessions.retain(|_, session| session.expires_at > now);
}

/// Node 登录回调的源上换成 `/admin/oidc/callback`。Kanidm 的严格回调
/// 必须同时登记这一条（`kanidm-init.sh` 会写）。
pub(crate) fn admin_redirect_uri(node_redirect: &reqwest::Url) -> reqwest::Url {
    let mut uri = node_redirect.clone();
    uri.set_path("/admin/oidc/callback");
    uri.set_query(None);
    uri.set_fragment(None);
    uri
}

/// `/admin/api` 的路由表。往后加的 route 都经过 [`require_admin_api`]。
pub(crate) fn api_router(state: Arc<HttpState>) -> Router<Arc<HttpState>> {
    // from_fn 不取 State，门禁要自己带一份。
    Router::new()
        .route("/me", get(me))
        .route("/nodes", get(list_nodes))
        .route("/nodes/{node_id}", delete(delete_node))
        .route("/nodes/{node_id}/rename", post(rename_node))
        .route("/nodes/{node_id}/revoke", post(revoke_node))
        .route("/auth-keys", post(create_auth_key))
        .route("/auth-keys/{key_id}/revoke", post(revoke_auth_key))
        .route("/policy", get(get_policy))
        .route("/health", get(health))
        .route("/ops/status", get(ops_status))
        .route("/ops/backup", post(run_backup))
        .fallback(api_not_found)
        .layer(middleware::from_fn_with_state(state, require_admin_api))
}

async fn require_admin_api(
    State(state): State<Arc<HttpState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(session) = session_from(&state, request.headers()) else {
        return unauthenticated();
    };
    request.extensions_mut().insert(session);
    next.run(request).await
}

fn session_from(state: &HttpState, headers: &HeaderMap) -> Option<AdminSession> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let id = cookie_value(raw, COOKIE)?;
    state.admin.session(id)
}

fn cookie_value<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    raw.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name && !value.is_empty()).then_some(value.trim())
    })
}

#[derive(Serialize)]
struct ApiError {
    error: &'static str,
    message: String,
}

fn json_response(status: StatusCode, body: &impl Serialize) -> Response {
    let payload = serde_json::to_string(body).expect("admin api json");
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        payload,
    )
        .into_response()
}

fn api_error(status: StatusCode, error: &'static str, message: impl Into<String>) -> Response {
    json_response(
        status,
        &ApiError {
            error,
            message: message.into(),
        },
    )
}

fn json_ok(body: &impl Serialize) -> Response {
    json_response(StatusCode::OK, body)
}

fn from_status(status: tonic::Status) -> Response {
    let (http_status, error) = match status.code() {
        tonic::Code::InvalidArgument => (StatusCode::BAD_REQUEST, "invalid_argument"),
        tonic::Code::NotFound => (StatusCode::NOT_FOUND, "not_found"),
        tonic::Code::AlreadyExists => (StatusCode::CONFLICT, "already_exists"),
        tonic::Code::PermissionDenied => (StatusCode::FORBIDDEN, "permission_denied"),
        tonic::Code::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };
    api_error(http_status, error, status.message())
}

fn admin_operator(session: &AdminSession) -> crate::admin::Operator {
    crate::admin::Operator::Admin {
        user: session.username.clone(),
    }
}

fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, Box<Response>> {
    match serde_json::from_slice(body) {
        Ok(parsed) => Ok(parsed),
        Err(_) => Err(Box::new(api_error(
            StatusCode::BAD_REQUEST,
            "invalid_argument",
            "请求体不是合法的 JSON",
        ))),
    }
}

fn unauthenticated() -> Response {
    api_error(
        StatusCode::UNAUTHORIZED,
        UNAUTHENTICATED,
        UNAUTHENTICATED_MESSAGE,
    )
}

fn not_found() -> Response {
    api_error(StatusCode::NOT_FOUND, NOT_FOUND, NOT_FOUND_MESSAGE)
}

#[derive(Serialize)]
struct MeBody {
    username: String,
    subject: String,
}

async fn me(Extension(session): Extension<AdminSession>) -> Response {
    json_response(
        StatusCode::OK,
        &MeBody {
            username: session.username,
            subject: session.subject,
        },
    )
}

async fn api_not_found() -> Response {
    not_found()
}

#[derive(Serialize)]
struct NodeBody {
    node_id: String,
    name: String,
    ipv4: String,
    ipv6: String,
    tags: Vec<String>,
    owner_user: Option<String>,
    expires_at_unix: Option<i64>,
    revoked: bool,
    revoked_at_unix: Option<i64>,
    created_at_unix: i64,
    online: bool,
}

#[derive(Serialize)]
struct NodeListBody {
    nodes: Vec<NodeBody>,
}

#[derive(Deserialize)]
struct RenameBody {
    name: String,
}

#[derive(Serialize)]
struct NameBody {
    name: String,
}

#[derive(Deserialize)]
struct CreateAuthKeyBody {
    expires_unix: i64,
    single_use: bool,
    tags: Vec<String>,
}

#[derive(Serialize)]
struct AuthKeyBody {
    auth_key: String,
    key_id: String,
}

#[derive(Serialize)]
struct PolicyHistBody {
    version: i64,
    created_at_unix: i64,
}

#[derive(Serialize)]
struct PolicyBody {
    version: i64,
    content: Option<String>,
    history: Vec<PolicyHistBody>,
}

#[derive(Serialize)]
struct RelayBody {
    punch_attempts_total: u64,
    punch_success_total: u64,
    punch_success_ratio: f64,
}

#[derive(Serialize)]
struct BackupBody {
    dir: String,
    readable: bool,
    latest: Option<String>,
    latest_unix: Option<i64>,
    age_secs: Option<i64>,
    count: u64,
    fresh: bool,
    fresh_within_secs: u64,
}

#[derive(Serialize)]
struct CertBody {
    name: &'static str,
    path: String,
    status: &'static str,
    not_after: Option<String>,
    not_after_unix: Option<i64>,
}

#[derive(Serialize)]
struct HealthBody {
    healthz: &'static str,
    online_nodes: u64,
    nodes: u64,
    revoked_nodes: u64,
    relay: Option<RelayBody>,
    backup: BackupBody,
    certs: Vec<CertBody>,
}

#[derive(Serialize)]
struct OpsStatusBody {
    backup: BackupBody,
    certs: Vec<CertBody>,
}

#[derive(Serialize)]
struct BackupRunBody {
    ok: bool,
    message: String,
}

fn scope_or_response(session: &AdminSession) -> Result<crate::store::NodeScope, Box<Response>> {
    crate::admin::list_scope(&admin_operator(session))
        .map_err(|status| Box::new(from_status(status)))
}

async fn listed_nodes(
    state: &HttpState,
    session: &AdminSession,
) -> Result<Vec<crate::store::ListedNode>, Box<Response>> {
    let scope = scope_or_response(session)?;
    state.store.list_nodes(&scope).await.map_err(|error| {
        tracing::error!(%error, "list nodes failed");
        Box::new(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "列出 Node 失败",
        ))
    })
}

async fn list_nodes(
    State(state): State<Arc<HttpState>>,
    Extension(session): Extension<AdminSession>,
) -> Response {
    let mut rows = match listed_nodes(&state, &session).await {
        Ok(rows) => rows,
        Err(response) => return *response,
    };
    rows.sort_by(|a, b| a.name.cmp(&b.name).then(a.node_id.cmp(&b.node_id)));
    let hub = state.console.hub.as_ref();
    let nodes = rows
        .into_iter()
        .map(|row| NodeBody {
            online: hub.is_some_and(|hub| hub.is_online(&row.node_id)),
            node_id: row.node_id,
            name: row.name,
            ipv4: row.ipv4,
            ipv6: row.ipv6,
            tags: row.tags,
            owner_user: row.owner_user,
            expires_at_unix: row.expires_at_unix,
            revoked: row.revoked,
            revoked_at_unix: row.revoked_at_unix,
            created_at_unix: row.created_at_unix,
        })
        .collect();
    json_ok(&NodeListBody { nodes })
}

async fn rename_node(
    State(state): State<Arc<HttpState>>,
    Extension(session): Extension<AdminSession>,
    axum::extract::Path(node_id): axum::extract::Path<String>,
    body: Bytes,
) -> Response {
    let RenameBody { name } = match parse_json(&body) {
        Ok(parsed) => parsed,
        Err(response) => return *response,
    };
    match crate::admin::rename_node(&state.store, &admin_operator(&session), &node_id, &name).await
    {
        Ok(name) => json_ok(&NameBody { name }),
        Err(status) => from_status(status),
    }
}

async fn delete_node(
    State(state): State<Arc<HttpState>>,
    Extension(session): Extension<AdminSession>,
    axum::extract::Path(node_id): axum::extract::Path<String>,
) -> Response {
    match crate::admin::delete_node(&state.store, &admin_operator(&session), &node_id).await {
        Ok(()) => {
            tracing::info!(user = %session.username, %node_id, "node deleted via admin http");
            json_ok(&serde_json::json!({}))
        }
        Err(status) => from_status(status),
    }
}

async fn revoke_node(
    State(state): State<Arc<HttpState>>,
    Extension(session): Extension<AdminSession>,
    axum::extract::Path(node_id): axum::extract::Path<String>,
) -> Response {
    let operator = admin_operator(&session);
    if let Err(status) = crate::admin::require_admin(&operator) {
        return from_status(status);
    }
    match crate::admin::revoke_node(&state.store, &node_id).await {
        Ok(()) => json_ok(&serde_json::json!({})),
        Err(status) => from_status(status),
    }
}

async fn create_auth_key(
    State(state): State<Arc<HttpState>>,
    Extension(session): Extension<AdminSession>,
    body: Bytes,
) -> Response {
    let CreateAuthKeyBody {
        expires_unix,
        single_use,
        tags,
    } = match parse_json(&body) {
        Ok(parsed) => parsed,
        Err(response) => return *response,
    };
    let operator = admin_operator(&session);
    if let Err(status) = crate::admin::require_admin(&operator) {
        return from_status(status);
    }
    match crate::admin::create_auth_key(&state.store, expires_unix, single_use, &tags).await {
        Ok((auth_key, key_id)) => {
            tracing::info!(user = %session.username, %key_id, "auth key issued via admin http");
            json_ok(&AuthKeyBody { auth_key, key_id })
        }
        Err(status) => from_status(status),
    }
}

async fn revoke_auth_key(
    State(state): State<Arc<HttpState>>,
    Extension(session): Extension<AdminSession>,
    axum::extract::Path(key_id): axum::extract::Path<String>,
) -> Response {
    let operator = admin_operator(&session);
    if let Err(status) = crate::admin::require_admin(&operator) {
        return from_status(status);
    }
    match crate::admin::revoke_auth_key(&state.store, &key_id).await {
        Ok(()) => {
            tracing::info!(user = %session.username, %key_id, "auth key revoked via admin http");
            json_ok(&serde_json::json!({}))
        }
        Err(status) => from_status(status),
    }
}

async fn get_policy(State(state): State<Arc<HttpState>>) -> Response {
    let current = match state.store.current_policy().await {
        Ok(current) => current,
        Err(error) => {
            tracing::error!(%error, "load current policy failed");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "读取 Policy 失败",
            );
        }
    };
    let (version, content) = match current {
        Some((version, content)) => (version, Some(content)),
        None => (0, None),
    };
    let history = match state.store.policy_history().await {
        Ok(rows) => rows
            .into_iter()
            .map(|row| PolicyHistBody {
                version: row.version,
                created_at_unix: row.created_at_unix,
            })
            .collect(),
        Err(error) => {
            tracing::error!(%error, "load policy history failed");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "读取 Policy 历史失败",
            );
        }
    };
    json_ok(&PolicyBody {
        version,
        content,
        history,
    })
}

async fn health(
    State(state): State<Arc<HttpState>>,
    Extension(session): Extension<AdminSession>,
) -> Response {
    let rows = match listed_nodes(&state, &session).await {
        Ok(rows) => rows,
        Err(response) => return *response,
    };
    let (backup, certs) = match ops_snapshot(&state).await {
        Ok(snapshot) => snapshot,
        Err(response) => return *response,
    };
    let relay = state.console.metrics.as_ref().map(|metrics| {
        let summary = metrics.punch_summary();
        RelayBody {
            punch_attempts_total: summary.attempts,
            punch_success_total: summary.success,
            punch_success_ratio: summary.ratio,
        }
    });
    json_ok(&HealthBody {
        healthz: "ok",
        online_nodes: state
            .console
            .hub
            .as_ref()
            .map(|hub| hub.online_nodes() as u64)
            .unwrap_or(0),
        nodes: rows.len() as u64,
        revoked_nodes: rows.iter().filter(|row| row.revoked).count() as u64,
        relay,
        backup,
        certs,
    })
}

async fn ops_status(State(state): State<Arc<HttpState>>) -> Response {
    match ops_snapshot(&state).await {
        Ok((backup, certs)) => json_ok(&OpsStatusBody { backup, certs }),
        Err(response) => *response,
    }
}

async fn ops_snapshot(state: &HttpState) -> Result<(BackupBody, Vec<CertBody>), Box<Response>> {
    let ops = state.console.ops.clone();
    tokio::task::spawn_blocking(move || (backup_status(&ops), cert_statuses(&ops)))
        .await
        .map_err(|error| {
            tracing::error!(%error, "ops snapshot failed");
            Box::new(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "读取备份或证书状态失败",
            ))
        })
}

async fn run_backup(
    State(state): State<Arc<HttpState>>,
    Extension(session): Extension<AdminSession>,
) -> Response {
    let script = state.console.ops.backup_script.clone();
    let db = state.console.ops.db_path.clone();
    let dest = state.console.ops.backup_dir.clone();
    let timeout = state.console.ops.backup_timeout;
    if !script.is_file() {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            format!(
                "未找到备份脚本 {}（设置 HZNET_BACKUP_SCRIPT）",
                script.display()
            ),
        );
    }
    let Some(db) = db.filter(|path| path.is_file()) else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "未配置数据库文件，无法备份",
        );
    };
    // ponytail: global lock, see ConsoleState::backup_busy.
    let Some(_guard) = state.console.try_backup() else {
        return api_error(StatusCode::CONFLICT, "conflict", "已有备份正在进行");
    };
    tracing::info!(user = %session.username, script = %script.display(), "admin backup started");
    let mut command = tokio::process::Command::new("bash");
    command
        .arg(&script)
        .arg("--db")
        .arg(&db)
        .arg("--dest")
        .arg(&dest)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = match tokio::time::timeout(timeout, async move {
        match command.spawn() {
            Ok(child) => child.wait_with_output().await,
            Err(error) => Err(error),
        }
    })
    .await
    {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            tracing::error!(%error, "backup spawn failed");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "无法启动备份",
            );
        }
        Err(_) => {
            tracing::warn!(user = %session.username, "admin backup timed out");
            return api_error(StatusCode::GATEWAY_TIMEOUT, "timeout", "备份超时");
        }
    };
    let stdout = brief(&String::from_utf8_lossy(&output.stdout));
    let stderr = brief(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        tracing::warn!(user = %session.username, code = ?output.status.code(), "admin backup failed");
        let message = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            "备份失败".to_string()
        };
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "backup_failed", message);
    }
    tracing::info!(user = %session.username, "admin backup finished");
    json_ok(&BackupRunBody {
        ok: true,
        message: if stdout.is_empty() {
            "备份完成".to_string()
        } else {
            stdout
        },
    })
}

fn brief(text: &str) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(500).collect()
}

fn backup_status(ops: &OpsConfig) -> BackupBody {
    let mut body = BackupBody {
        dir: ops.backup_dir.display().to_string(),
        readable: true,
        latest: None,
        latest_unix: None,
        age_secs: None,
        count: 0,
        fresh: false,
        fresh_within_secs: BACKUP_FRESH_SECS,
    };
    let entries = match std::fs::read_dir(&ops.backup_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return body,
        Err(error) => {
            tracing::warn!(%error, dir = %ops.backup_dir.display(), "backup dir unreadable");
            body.readable = false;
            return body;
        }
    };
    let now = crate::store::unix_now();
    let mut latest: Option<(String, i64)> = None;
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !(name.starts_with("hz-coord-") && name.ends_with(".db")) {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let Some(modified) = meta.modified().ok().and_then(unix_time) else {
            continue;
        };
        body.count += 1;
        if latest.as_ref().is_none_or(|(_, ts)| modified >= *ts) {
            latest = Some((name, modified));
        }
    }
    if let Some((name, ts)) = latest {
        let age = now.saturating_sub(ts);
        body.fresh = (age as u64) <= BACKUP_FRESH_SECS;
        body.age_secs = Some(age);
        body.latest_unix = Some(ts);
        body.latest = Some(name);
    }
    body
}

fn unix_time(time: SystemTime) -> Option<i64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs() as i64)
}

fn cert_statuses(ops: &OpsConfig) -> Vec<CertBody> {
    CERT_NAMES
        .into_iter()
        .map(|name| cert_status(ops, name))
        .collect()
}

fn cert_status(ops: &OpsConfig, name: &'static str) -> CertBody {
    let path = ops.tls_dir.join(name).join("fullchain.pem");
    let mut body = CertBody {
        name,
        path: path.display().to_string(),
        status: "missing",
        not_after: None,
        not_after_unix: None,
    };
    if !path.exists() {
        return body;
    }
    if std::fs::File::open(&path).is_err() {
        body.status = "unreadable";
        return body;
    }
    let Some(not_after) = cert_not_after(&path) else {
        body.status = "unreadable";
        return body;
    };
    body.not_after_unix = parse_not_after(&not_after);
    body.not_after = Some(not_after);
    let window = ops.cert_warn_days.saturating_mul(86_400);
    body.status = match (openssl_checkend(&path, 0), openssl_checkend(&path, window)) {
        (Some(false), _) => "expired",
        (Some(true), Some(false)) => "expiring",
        (Some(true), Some(true)) => "ok",
        _ => "unreadable",
    };
    body
}

fn cert_not_after(path: &Path) -> Option<String> {
    let iso = openssl_text(path, &["-noout", "-enddate", "-dateopt", "iso_8601"]);
    let text = if iso.as_ref().is_some_and(|text| text.contains("notAfter=")) {
        iso
    } else {
        openssl_text(path, &["-noout", "-enddate"])
    }?;
    let line = text.lines().next()?.trim();
    let value = line.strip_prefix("notAfter=")?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn openssl_text(path: &Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("openssl")
        .arg("x509")
        .arg("-in")
        .arg(path)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn openssl_checkend(path: &Path, seconds: u64) -> Option<bool> {
    let output = std::process::Command::new("openssl")
        .args(["x509", "-checkend"])
        .arg(seconds.to_string())
        .arg("-noout")
        .arg("-in")
        .arg(path)
        .output()
        .ok()?;
    Some(output.status.success())
}

fn parse_not_after(text: &str) -> Option<i64> {
    let text = text.trim();
    // openssl `-dateopt iso_8601`：`2027-10-26 18:02:50Z`（空格，不是 RFC3339 的 T）。
    if let Ok(parsed) = chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%SZ") {
        return Some(parsed.and_utc().timestamp());
    }
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(text) {
        return Some(parsed.timestamp());
    }
    // 不带 `-dateopt` 的回退。月份缩写是 openssl 的英文，不跟系统 locale。
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mut parts = normalized.split(' ');
    let month_name = parts.next()?;
    let month = MONTHS.iter().position(|name| *name == month_name)? as u32 + 1;
    let day: u32 = parts.next()?.parse().ok()?;
    let time = parts.next()?;
    let year: i32 = parts.next()?.parse().ok()?;
    if parts.next() != Some("GMT") {
        return None;
    }
    let naive = chrono::NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(
        time.split(':').next()?.parse().ok()?,
        time.split(':').nth(1)?.parse().ok()?,
        time.split(':').nth(2)?.parse().ok()?,
    )?;
    Some(naive.and_utc().timestamp())
}

/// `/admin` 与 `/admin/`。未登录去 `/admin/login`；已登录返回静态壳。
pub(crate) async fn browser_entry(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> Response {
    gated(&state, &headers, crate::admin_ui::index())
}

pub(crate) async fn console_css(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> Response {
    gated(&state, &headers, crate::admin_ui::css())
}

pub(crate) async fn console_js(
    State(state): State<Arc<HttpState>>,
    headers: HeaderMap,
) -> Response {
    gated(&state, &headers, crate::admin_ui::js())
}

fn login_redirect(state: &HttpState, headers: &HeaderMap) -> Option<Response> {
    session_from(state, headers)
        .is_none()
        .then(|| Redirect::temporary("/admin/login").into_response())
}

fn gated(state: &HttpState, headers: &HeaderMap, response: Response) -> Response {
    login_redirect(state, headers).unwrap_or(response)
}

pub(crate) async fn login(State(state): State<Arc<HttpState>>) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Html("<h1>无法登录</h1><p>此服务器未配置交互式登录（OIDC）。</p>"),
        )
            .into_response();
    };
    let redirect = admin_redirect_uri(oidc.redirect_uri());
    let oidc_state = oidc::new_login_token("a");
    let nonce = oidc::new_login_token("n");
    let verifier = oidc::new_pkce_verifier();
    state
        .admin
        .begin(oidc_state.clone(), nonce.clone(), verifier.clone());
    let request = oidc.authorization_request_to(&redirect, &oidc_state, &nonce, &verifier);
    tracing::info!("admin oidc authorization redirect issued");
    Redirect::temporary(request.url.as_str()).into_response()
}

#[derive(Deserialize)]
pub(crate) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub(crate) async fn callback(
    State(state): State<Arc<HttpState>>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Html("<h1>无法登录</h1><p>此服务器未配置交互式登录（OIDC）。</p>"),
        )
            .into_response();
    };
    if let Some(error) = query.error.as_deref() {
        if let Some(oidc_state) = query.state.as_deref() {
            state.admin.discard(oidc_state);
        }
        tracing::warn!(%error, "admin oidc callback received error");
        return Html(format!(
            "<h1>登录失败</h1><p>身份提供方返回错误：{}</p>",
            escape_html(error)
        ))
        .into_response();
    }
    let (Some(code), Some(oidc_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return (StatusCode::BAD_REQUEST, "回调缺少 code 或 state").into_response();
    };
    let Some((nonce, verifier)) = state.admin.take_pending(oidc_state) else {
        return (
            StatusCode::BAD_REQUEST,
            "登录已过期或状态无效，请重新打开 /admin/login",
        )
            .into_response();
    };
    let redirect = admin_redirect_uri(oidc.redirect_uri());
    let claims = match oidc.exchange_at(&redirect, code, &verifier, &nonce).await {
        Ok(claims) => claims,
        Err(error) => {
            tracing::error!(%error, "admin oidc token exchange failed");
            return Html(
                "<h1>登录失败</h1><p>与身份提供方的通信未完成，请重新打开 /admin/login。</p>",
            )
            .into_response();
        }
    };
    finish_login(&state, &redirect, claims)
}

fn finish_login(state: &HttpState, redirect: &reqwest::Url, claims: UserClaims) -> Response {
    if !claims.is_admin() {
        tracing::warn!(user = %claims.preferred_username, "admin console rejected non-admin");
        return (
            StatusCode::FORBIDDEN,
            Html("<h1>无权进入</h1><p>只有 hznet_admins 的成员可以进入 Admin Console。</p>"),
        )
            .into_response();
    }
    let id = state
        .admin
        .open_session(&claims.preferred_username, &claims.subject);
    tracing::info!(user = %claims.preferred_username, "admin session opened");
    let mut response = Redirect::temporary("/admin/").into_response();
    let cookie = set_cookie(&id, redirect.scheme() == "https");
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("session cookie is ascii"),
    );
    response
}

fn set_cookie(id: &str, secure: bool) -> String {
    let mut cookie = format!(
        "{COOKIE}={id}; HttpOnly; SameSite=Lax; Path=/admin; Max-Age={}",
        SESSION_TTL.as_secs()
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    //! 不连接 Kanidm。[`spawn_idp`] 在 127.0.0.1 上提供 token 与 userinfo，
    //! `cargo test -p hz-coord admin_http` 与 CI 的 `cargo test --all` 都跑这些测试。
    //! 真实 Kanidm 在 `tests/kanidm_login.rs`，`#[ignore]`，由
    //! `scripts/test/kanidm/run.sh` 显式启用。静态页没有前端构建。
    //! 证书用例调用本机 openssl。约束说明见 docs/admin-console-v1.md「测试」。
    use std::sync::Mutex;

    use axum::Router;
    use axum::extract::State;
    use axum::http::header;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use super::*;
    use crate::addr::AddressConfig;
    use crate::http::serve_http;
    use crate::login::LoginRegistry;
    use crate::oidc::{OidcClient, OidcConfig};
    use crate::store::Store;

    #[derive(Clone)]
    struct IdpState {
        nonce: Arc<Mutex<Option<String>>>,
        groups: Vec<String>,
    }

    struct Idp {
        base: String,
        nonce: Arc<Mutex<Option<String>>>,
    }

    async fn spawn_idp(groups: &[&str]) -> Idp {
        let nonce = Arc::new(Mutex::new(None));
        let state = IdpState {
            nonce: nonce.clone(),
            groups: groups.iter().map(|group| (*group).to_owned()).collect(),
        };
        let app = Router::new()
            .route("/token", post(idp_token))
            .route("/userinfo", get(idp_userinfo))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Idp {
            base: format!("http://{addr}"),
            nonce,
        }
    }

    async fn idp_token(State(state): State<IdpState>) -> impl IntoResponse {
        let nonce = state
            .nonce
            .lock()
            .expect("nonce")
            .clone()
            .unwrap_or_default();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"nonce":"{nonce}"}}"#).as_bytes());
        let body = serde_json::json!({
            "access_token": "test-access-token",
            "id_token": format!("{header}.{payload}.sig"),
            "token_type": "Bearer",
        });
        (
            [(header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
    }

    async fn idp_userinfo(State(state): State<IdpState>) -> impl IntoResponse {
        let body = serde_json::json!({
            "sub": "sub-alice",
            "preferred_username": "alice",
            "groups": state.groups,
        });
        (
            [(header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
    }

    fn oidc_for(idp: &Idp) -> OidcClient {
        // 主机不必是正在听的 coord：回调由测试直接打到 coord，
        // 这里只验证授权 URL 上的 redirect_uri 被换成了 /admin/oidc/callback。
        let redirect: reqwest::Url = "http://127.0.0.1:9/oidc/callback".parse().unwrap();
        OidcClient::from_endpoints(
            OidcConfig {
                issuer: format!("{}/issuer", idp.base).parse().unwrap(),
                client_id: "hznet-coord".to_owned(),
                client_secret: "secret".to_owned(),
                redirect_uri: redirect,
                ca_cert: None,
            },
            format!("{}/authorize", idp.base).parse().unwrap(),
            format!("{}/token", idp.base).parse().unwrap(),
            format!("{}/userinfo", idp.base).parse().unwrap(),
        )
    }

    async fn start(oidc: Option<OidcClient>) -> (String, crate::http::HttpHandle) {
        let store = Store::open_in_memory(AddressConfig::default())
            .await
            .unwrap();
        start_with(oidc, store, ConsoleState::default()).await
    }

    async fn start_with(
        oidc: Option<OidcClient>,
        store: Store,
        console: ConsoleState,
    ) -> (String, crate::http::HttpHandle) {
        let state = Arc::new(HttpState {
            oidc,
            logins: Arc::new(LoginRegistry::new()),
            store,
            login_node_ttl_secs: 90 * 86_400,
            dist: None,
            admin: AdminGate::default(),
            console,
        });
        let handle = serve_http("127.0.0.1:0".parse().unwrap(), state)
            .await
            .unwrap();
        (format!("http://{}", handle.local_addr), handle)
    }

    fn http() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    async fn assert_api_error(
        response: reqwest::Response,
        status: u16,
        error: &str,
        message: &str,
    ) {
        assert_eq!(response.status(), status);
        let content_type = response.headers()["content-type"].to_str().unwrap();
        assert!(
            content_type.starts_with("application/json"),
            "{content_type}"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body: serde_json::Map<String, serde_json::Value> = response.json().await.unwrap();
        assert_eq!(body.len(), 2, "{body:?}");
        assert_eq!(body["error"], error);
        assert_eq!(body["message"], message);
    }

    async fn callback_on(client: &reqwest::Client, base: &str, idp: &Idp) -> reqwest::Response {
        let start = client
            .get(format!("{base}/admin/login"))
            .send()
            .await
            .unwrap();
        assert_eq!(start.status(), 307);
        let location = reqwest::Url::parse(start.headers()["location"].to_str().unwrap()).unwrap();
        assert_eq!(
            location
                .query_pairs()
                .find(|(k, _)| k == "redirect_uri")
                .unwrap()
                .1,
            "http://127.0.0.1:9/admin/oidc/callback"
        );
        assert_eq!(
            location
                .query_pairs()
                .find(|(key, _)| key == "code_challenge_method")
                .unwrap()
                .1,
            "S256"
        );
        let nonce = location
            .query_pairs()
            .find(|(key, _)| key == "nonce")
            .unwrap()
            .1
            .into_owned();
        let oidc_state = location
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        *idp.nonce.lock().expect("nonce") = Some(nonce);
        client
            .get(format!("{base}/admin/oidc/callback"))
            .query(&[("code", "ok"), ("state", oidc_state.as_str())])
            .send()
            .await
            .unwrap()
    }

    async fn login_cookie(client: &reqwest::Client, base: &str, idp: &Idp) -> String {
        let callback = callback_on(client, base, idp).await;
        assert_eq!(callback.status(), 307, "admin login");
        callback.headers()["set-cookie"]
            .to_str()
            .expect("set-cookie")
            .split(';')
            .next()
            .expect("cookie pair")
            .to_owned()
    }

    #[tokio::test]
    async fn unauthenticated_api_is_401_json_and_browser_redirects_to_login() {
        let (base, _handle) = start(None).await;
        let client = http();

        let me = client
            .get(format!("{base}/admin/api/me"))
            .header("accept", "text/html")
            .send()
            .await
            .unwrap();
        assert_api_error(me, 401, UNAUTHENTICATED, UNAUTHENTICATED_MESSAGE).await;

        let forged = client
            .get(format!("{base}/admin/api/me"))
            .header("cookie", "hz_admin=deadbeef")
            .send()
            .await
            .unwrap();
        assert_api_error(forged, 401, UNAUTHENTICATED, UNAUTHENTICATED_MESSAGE).await;

        // 门禁包住每条主路径，也包括清单 / Policy 写入 / 重启升级这些没有实现的路径。
        for (method, path) in [
            ("GET", "/admin/api/me"),
            ("GET", "/admin/api/nodes"),
            ("DELETE", "/admin/api/nodes/n1"),
            ("POST", "/admin/api/nodes/n1/rename"),
            ("POST", "/admin/api/nodes/n1/revoke"),
            ("POST", "/admin/api/auth-keys"),
            ("GET", "/admin/api/auth-keys"),
            ("POST", "/admin/api/auth-keys/k1/revoke"),
            ("GET", "/admin/api/policy"),
            ("POST", "/admin/api/policy"),
            ("PUT", "/admin/api/policy"),
            ("GET", "/admin/api/health"),
            ("GET", "/admin/api/ops/status"),
            ("POST", "/admin/api/ops/backup"),
            ("POST", "/admin/api/ops/restart"),
            ("POST", "/admin/api/ops/upgrade"),
            ("GET", "/admin/api/no-such"),
        ] {
            let response = client
                .request(method.parse().unwrap(), format!("{base}{path}"))
                .send()
                .await
                .unwrap();
            let status = response.status();
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let cache = response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let text = response.text().await.unwrap_or_default();
            assert!(
                status == StatusCode::UNAUTHORIZED
                    && content_type.starts_with("application/json")
                    && cache == "no-store"
                    && text.contains("\"error\":\"unauthenticated\"")
                    && text.contains(UNAUTHENTICATED_MESSAGE),
                "{method} {path} -> {status} {content_type} {text}"
            );
        }

        for path in [
            "/admin",
            "/admin/",
            "/admin/console.css",
            "/admin/console.js",
        ] {
            let response = client.get(format!("{base}{path}")).send().await.unwrap();
            assert_eq!(response.status(), 307, "{path}");
            assert_eq!(response.headers()["location"], "/admin/login");
        }

        let login = client
            .get(format!("{base}/admin/login"))
            .send()
            .await
            .unwrap();
        assert_eq!(login.status(), 503);
        assert!(login.text().await.unwrap().contains("未配置"));

        let health = client.get(format!("{base}/healthz")).send().await.unwrap();
        assert_eq!(health.status(), 200);
        assert_eq!(health.text().await.unwrap(), "ok");
    }

    #[tokio::test]
    async fn hznet_admins_session_can_read_me() {
        let idp = spawn_idp(&["idm_all_persons@localhost", "hznet_admins@localhost"]).await;
        let (base, _handle) = start(Some(oidc_for(&idp))).await;
        let client = http();

        let callback = callback_on(&client, &base, &idp).await;
        assert_eq!(callback.status(), 307);
        assert_eq!(callback.headers()["location"], "/admin/");
        let set_cookie = callback.headers()["set-cookie"].to_str().unwrap();
        assert!(set_cookie.starts_with("hz_admin=s"), "{set_cookie}");
        assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
        assert!(set_cookie.contains("SameSite=Lax"), "{set_cookie}");
        assert!(set_cookie.contains("Path=/admin"), "{set_cookie}");
        assert!(!set_cookie.contains("Secure"), "{set_cookie}");
        let cookie = set_cookie.split(';').next().unwrap();

        let me = client
            .get(format!("{base}/admin/api/me"))
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(me.status(), 200);
        assert_eq!(me.headers()["cache-control"], "no-store");
        let body: serde_json::Map<String, serde_json::Value> = me.json().await.unwrap();
        assert_eq!(body.len(), 2, "{body:?}");
        assert_eq!(body["username"], "alice");
        assert_eq!(body["subject"], "sub-alice");

        let missing = client
            .get(format!("{base}/admin/api/no-such"))
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        assert_api_error(missing, 404, NOT_FOUND, NOT_FOUND_MESSAGE).await;

        let page = client
            .get(format!("{base}/admin/"))
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(page.status(), 200);
        assert!(
            page.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        assert_eq!(page.headers()["cache-control"], "no-store");
        let html = page.text().await.unwrap();
        for needle in [
            "href=\"#nodes\">Nodes",
            "href=\"#keys\">Auth Keys",
            "href=\"#ops\">健康与运维",
            "href=\"#policy\">Policy",
            "href=\"#wizard\">部署向导",
            "id=\"nodes-table\"",
            "id=\"key-create\"",
            "id=\"key-revoke\"",
            "id=\"key-once\"",
            "id=\"policy-body\"",
            "id=\"ops-health\"",
            "id=\"ops-backup\"",
            "id=\"backup-run\"",
            "本页不执行命令",
            "/admin/console.css",
            "/admin/console.js",
        ] {
            assert!(html.contains(needle), "{needle} missing");
        }
        assert!(!html.contains("即将就绪"));
        assert!(!html.contains("systemctl"));

        let bare = client
            .get(format!("{base}/admin"))
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(bare.status(), 200);
        assert!(bare.text().await.unwrap().contains("Admin Console"));

        let css = client
            .get(format!("{base}/admin/console.css"))
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(css.status(), 200);
        assert!(
            css.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/css")
        );
        assert!(css.text().await.unwrap().contains("nav a"));

        let js = client
            .get(format!("{base}/admin/console.js"))
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(js.status(), 200);
        assert!(
            js.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with("text/javascript")
        );
        let source = js.text().await.unwrap();
        assert!(source.contains("api(\"/admin/api/me\")"));
        for needle in [
            "\"/admin/api/nodes\"",
            "\"/admin/api/auth-keys\"",
            "\"/admin/api/policy\"",
            "\"/admin/api/health\"",
            "\"/admin/api/ops/status\"",
            "\"/admin/api/ops/backup\"",
            "method: \"POST\"",
            "method: \"DELETE\"",
        ] {
            assert!(source.contains(needle), "{needle} missing");
        }
        // 签发是 POST /admin/api/auth-keys。没有列表，不能 GET 这个集合。
        assert!(!source.contains("api(\"/admin/api/auth-keys\")"));
        assert!(!source.contains("fetch(\"/admin/api/auth-keys\")"));
        assert!(!source.contains("systemctl"));

        let replay = client
            .get(format!("{base}/admin/oidc/callback"))
            .query(&[("code", "ok"), ("state", "not-the-one")])
            .send()
            .await
            .unwrap();
        assert_eq!(replay.status(), 400);
    }

    #[tokio::test]
    async fn oidc_login_outside_hznet_admins_does_not_open_a_session() {
        let idp = spawn_idp(&["hznet_users@localhost"]).await;
        let (base, _handle) = start(Some(oidc_for(&idp))).await;
        let client = http();

        let callback = callback_on(&client, &base, &idp).await;
        assert_eq!(callback.status(), 403);
        assert!(callback.headers().get("set-cookie").is_none());
        let page = callback.text().await.unwrap();
        assert!(page.contains("hznet_admins"), "{page}");

        let me = client
            .get(format!("{base}/admin/api/me"))
            .send()
            .await
            .unwrap();
        assert_api_error(me, 401, UNAUTHENTICATED, UNAUTHENTICATED_MESSAGE).await;
    }

    #[tokio::test]
    async fn admin_api_closed_routes_and_backup_misconfig() {
        let root = tempfile::tempdir().unwrap();
        let missing_script = root.path().join("missing-backup.sh");
        let idp = spawn_idp(&["hznet_admins@localhost"]).await;
        let store = Store::open_in_memory(AddressConfig::default())
            .await
            .unwrap();
        let console = ConsoleState {
            ops: OpsConfig {
                backup_script: missing_script.clone(),
                db_path: None,
                ..OpsConfig::default()
            },
            ..ConsoleState::default()
        };
        let (base, _handle) = start_with(Some(oidc_for(&idp)), store, console).await;
        let client = http();
        let cookie = login_cookie(&client, &base, &idp).await;

        let no_list = client
            .get(format!("{base}/admin/api/auth-keys"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(no_list.status(), 405, "auth key list must not exist");
        let no_list_body = no_list.text().await.unwrap();
        assert!(
            !no_list_body.contains("hznet."),
            "list body leaked a key: {no_list_body}"
        );

        for method in ["POST", "PUT"] {
            let write_policy = client
                .request(method.parse().unwrap(), format!("{base}/admin/api/policy"))
                .header("cookie", &cookie)
                .json(&serde_json::json!({"content": "groups = []\n"}))
                .send()
                .await
                .unwrap();
            assert_eq!(write_policy.status(), 405, "{method} /admin/api/policy");
        }

        for path in ["/admin/api/ops/restart", "/admin/api/ops/upgrade"] {
            let response = client
                .post(format!("{base}{path}"))
                .header("cookie", &cookie)
                .send()
                .await
                .unwrap();
            assert_api_error(response, 404, NOT_FOUND, NOT_FOUND_MESSAGE).await;
        }

        let bad_json = client
            .post(format!("{base}/admin/api/auth-keys"))
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body("not-json")
            .send()
            .await
            .unwrap();
        assert_api_error(bad_json, 400, "invalid_argument", "请求体不是合法的 JSON").await;

        let missing = client
            .post(format!("{base}/admin/api/ops/backup"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_api_error(
            missing,
            503,
            "unavailable",
            &format!(
                "未找到备份脚本 {}（设置 HZNET_BACKUP_SCRIPT）",
                missing_script.display()
            ),
        )
        .await;

        let script = root.path().join("backup.sh");
        let db = root.path().join("hznet.db");
        std::fs::write(&db, b"").unwrap();
        std::fs::write(&script, "#!/bin/bash\necho 'disk full' >&2\nexit 1\n").unwrap();
        let failed = ConsoleState {
            ops: OpsConfig {
                backup_script: script,
                db_path: Some(db),
                backup_dir: root.path().join("backups"),
                ..OpsConfig::default()
            },
            ..ConsoleState::default()
        };
        let store = Store::open_in_memory(AddressConfig::default())
            .await
            .unwrap();
        let (base, _handle) = start_with(Some(oidc_for(&idp)), store, failed).await;
        let cookie = login_cookie(&client, &base, &idp).await;
        let ran = client
            .post(format!("{base}/admin/api/ops/backup"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_api_error(ran, 500, "backup_failed", "disk full").await;
    }

    #[test]
    fn admin_redirect_keeps_origin_and_replaces_path() {
        let node: reqwest::Url = "https://coord.example.com/oidc/callback?x=1"
            .parse()
            .unwrap();
        assert_eq!(
            admin_redirect_uri(&node).as_str(),
            "https://coord.example.com/admin/oidc/callback"
        );
        assert!(set_cookie("sabc", true).ends_with("; Secure"));
        assert!(!set_cookie("sabc", false).contains("Secure"));
    }

    fn write_cert(dir: &std::path::Path, name: &str, extra: &[&str]) {
        let sub = dir.join(name);
        std::fs::create_dir_all(&sub).unwrap();
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
            ])
            .arg(sub.join("key.pem"))
            .arg("-out")
            .arg(sub.join("fullchain.pem"))
            .args(["-nodes", "-subj", "/CN=coord.example.com"])
            .args(extra)
            .status()
            .unwrap();
        assert!(status.success(), "openssl req {name}");
    }

    #[tokio::test]
    async fn admin_api_nodes_keys_policy_health_and_backup() {
        let root = tempfile::tempdir().unwrap();
        let backup_dir = root.path().join("backups");
        let tls_dir = root.path().join("tls");
        let db = root.path().join("hznet.db");
        std::fs::create_dir_all(&backup_dir).unwrap();
        std::fs::write(&db, b"").unwrap();
        std::fs::write(backup_dir.join("notes.txt"), b"ignore").unwrap();
        std::fs::write(backup_dir.join("kanidm-1.backup.jsonl"), b"ignore").unwrap();
        let recent = backup_dir.join("hz-coord-new.db");
        let old = backup_dir.join("hz-coord-old.db");
        std::fs::write(&recent, b"new").unwrap();
        std::fs::write(&old, b"old").unwrap();
        let file = std::fs::File::options().write(true).open(&old).unwrap();
        file.set_modified(
            std::time::SystemTime::now() - std::time::Duration::from_secs(40 * 60 * 60),
        )
        .unwrap();
        write_cert(&tls_dir, "coord", &["-days", "365"]);
        write_cert(&tls_dir, "relay", &["-days", "1"]);

        let script = root.path().join("backup.sh");
        std::fs::write(
            &script,
            r#"#!/bin/bash
dest=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--dest" ]; then dest="$arg"; fi
  prev="$arg"
done
mkdir -p "$dest"
printf '%s\n' "$@" > "$dest/args"
touch "$dest/started"
if [ -f "$dest/stall" ]; then
  sleep 30
fi
echo "已备份 fake"
"#,
        )
        .unwrap();

        let store = Store::open_in_memory(AddressConfig::default())
            .await
            .unwrap();
        let alpha = store
            .register_node(
                &[1u8; 32],
                &[2u8; 32],
                "alpha",
                &["server".into()],
                None,
                None,
            )
            .await
            .unwrap();
        let beta = store
            .register_node(
                &[3u8; 32],
                &[4u8; 32],
                "beta",
                &[],
                None,
                Some(1_900_000_000),
            )
            .await
            .unwrap();
        let hub = Arc::new(crate::map_stream::MapHub::new());
        let _stream = hub.register(alpha.id.clone());
        let metrics = Arc::new(crate::metrics::Metrics::new().unwrap());
        metrics.note_path_report(&alpha.id, 10, 4);
        metrics.note_path_report(&alpha.id, 13, 6);
        let ops = OpsConfig {
            backup_script: script,
            db_path: Some(db.clone()),
            backup_dir: backup_dir.clone(),
            tls_dir,
            backup_timeout: std::time::Duration::from_millis(800),
            ..OpsConfig::default()
        };
        let console = ConsoleState::with_runtime(ops, hub, metrics);

        let idp = spawn_idp(&["hznet_admins@localhost"]).await;
        let (base, _handle) = start_with(Some(oidc_for(&idp)), store.clone(), console).await;
        let client = http();
        let callback = callback_on(&client, &base, &idp).await;
        let cookie = callback.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        let listed = client
            .get(format!("{base}/admin/api/nodes"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status(), 200);
        let listed: serde_json::Value = listed.json().await.unwrap();
        let nodes = listed["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0]["name"], "alpha");
        assert_eq!(nodes[0]["online"], true);
        assert_eq!(nodes[0]["revoked"], false);
        assert!(nodes[0]["created_at_unix"].as_i64().unwrap() > 0);
        assert_eq!(nodes[0]["tags"][0], "server");
        assert_eq!(nodes[1]["name"], "beta");
        assert_eq!(nodes[1]["online"], false);
        assert_eq!(nodes[1]["expires_at_unix"], 1_900_000_000);
        assert!(nodes[1]["revoked_at_unix"].is_null());

        let renamed = client
            .post(format!("{base}/admin/api/nodes/{}/rename", beta.id))
            .header("cookie", &cookie)
            .json(&serde_json::json!({"name": "Beta Host"}))
            .send()
            .await
            .unwrap();
        assert_eq!(renamed.status(), 200);
        assert_eq!(
            renamed.json::<serde_json::Value>().await.unwrap()["name"],
            "beta-host"
        );

        let clash = client
            .post(format!("{base}/admin/api/nodes/{}/rename", beta.id))
            .header("cookie", &cookie)
            .json(&serde_json::json!({"name": "alpha"}))
            .send()
            .await
            .unwrap();
        assert_api_error(clash, 409, "already_exists", "Node Name 已存在：alpha").await;

        let revoked = client
            .post(format!("{base}/admin/api/nodes/{}/revoke", alpha.id))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(revoked.status(), 200);
        let again = client
            .get(format!("{base}/admin/api/nodes"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        let alpha_row = again["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["node_id"] == alpha.id)
            .unwrap();
        assert_eq!(alpha_row["revoked"], true);
        assert!(alpha_row["revoked_at_unix"].as_i64().unwrap() > 0);

        let health = client
            .get(format!("{base}/admin/api/health"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(health.status(), 200);
        assert_eq!(health.headers()["cache-control"], "no-store");
        let health: serde_json::Value = health.json().await.unwrap();
        assert_eq!(health["healthz"], "ok");
        assert_eq!(health["online_nodes"], 1);
        assert_eq!(health["nodes"], 2);
        assert_eq!(health["revoked_nodes"], 1);
        assert_eq!(health["relay"]["punch_attempts_total"], 3);
        assert_eq!(health["relay"]["punch_success_total"], 2);
        let ratio = health["relay"]["punch_success_ratio"].as_f64().unwrap();
        assert!((ratio - (2.0 / 3.0)).abs() < 1e-9, "{ratio}");
        assert_eq!(health["backup"]["count"], 2);
        assert_eq!(health["backup"]["latest"], "hz-coord-new.db");
        assert_eq!(health["backup"]["fresh"], true);
        assert_eq!(health["backup"]["readable"], true);
        assert_eq!(health["backup"]["fresh_within_secs"], 36 * 60 * 60);
        let certs = health["certs"].as_array().unwrap();
        assert_eq!(certs.len(), 3);
        assert_eq!(certs[0]["name"], "coord");
        assert_eq!(certs[0]["status"], "ok");
        assert!(certs[0]["not_after_unix"].as_i64().unwrap() > crate::store::unix_now());
        assert_eq!(certs[1]["name"], "relay");
        assert_eq!(certs[1]["status"], "expiring");
        assert_eq!(certs[2]["status"], "missing");

        let ops = client
            .get(format!("{base}/admin/api/ops/status"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(ops["backup"]["latest"], "hz-coord-new.db");
        assert_eq!(ops["certs"][2]["status"], "missing");

        let deleted = client
            .delete(format!("{base}/admin/api/nodes/{}", alpha.id))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(deleted.status(), 200);
        let missing_node = client
            .delete(format!("{base}/admin/api/nodes/{}", alpha.id))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_api_error(
            missing_node,
            404,
            "not_found",
            &format!("Node {} 不存在", alpha.id),
        )
        .await;

        let bad_key = client
            .post(format!("{base}/admin/api/auth-keys"))
            .header("cookie", &cookie)
            .json(&serde_json::json!({"expires_unix": crate::store::unix_now() + 3600, "single_use": true, "tags": []}))
            .send()
            .await
            .unwrap();
        assert_eq!(bad_key.status(), 400);
        let bad_key: serde_json::Value = bad_key.json().await.unwrap();
        assert_eq!(bad_key["error"], "invalid_argument");
        assert!(bad_key["message"].as_str().unwrap().contains("Tag"));

        let created = client
            .post(format!("{base}/admin/api/auth-keys"))
            .header("cookie", &cookie)
            .json(&serde_json::json!({
                "expires_unix": crate::store::unix_now() + 3600,
                "single_use": true,
                "tags": ["server"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), 200);
        assert_eq!(created.headers()["cache-control"], "no-store");
        let created: serde_json::Value = created.json().await.unwrap();
        let auth_key = created["auth_key"].as_str().unwrap();
        let key_id = created["key_id"].as_str().unwrap();
        assert!(auth_key.starts_with("hznet."), "{auth_key}");
        assert_eq!(key_id.len(), 32);

        let no_list = client
            .get(format!("{base}/admin/api/auth-keys"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_ne!(no_list.status(), 200);

        let revoked_key = client
            .post(format!("{base}/admin/api/auth-keys/{key_id}/revoke"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(revoked_key.status(), 200);
        let revoked_again = client
            .post(format!("{base}/admin/api/auth-keys/{key_id}/revoke"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(revoked_again.status(), 200);
        let unknown_key = client
            .post(format!("{base}/admin/api/auth-keys/no-such-key/revoke"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_api_error(unknown_key, 404, "not_found", "Auth Key no-such-key 不存在").await;

        let policy = client
            .get(format!("{base}/admin/api/policy"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(policy["version"], 0);
        assert!(policy["content"].is_null());
        assert_eq!(policy["history"].as_array().unwrap().len(), 0);
        let version = store.push_policy("groups = []\n").await.unwrap();
        let policy = client
            .get(format!("{base}/admin/api/policy"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(policy["version"], version);
        assert_eq!(policy["content"], "groups = []\n");
        assert_eq!(policy["history"][0]["version"], version);
        assert!(policy["history"][0]["created_at_unix"].as_i64().unwrap() > 0);
        let write_policy = client
            .post(format!("{base}/admin/api/policy"))
            .header("cookie", &cookie)
            .json(&serde_json::json!({"content": "nope"}))
            .send()
            .await
            .unwrap();
        assert_eq!(write_policy.status(), 405);

        let ran = client
            .post(format!("{base}/admin/api/ops/backup"))
            .header("cookie", &cookie)
            .json(&serde_json::json!({"cmd": "rm -rf /"}))
            .send()
            .await
            .unwrap();
        assert_eq!(ran.status(), 200);
        let ran: serde_json::Value = ran.json().await.unwrap();
        assert_eq!(ran["ok"], true);
        assert!(ran["message"].as_str().unwrap().contains("已备份"));
        let args = std::fs::read_to_string(backup_dir.join("args")).unwrap();
        assert_eq!(
            args,
            format!("--db\n{}\n--dest\n{}\n", db.display(), backup_dir.display())
        );

        std::fs::write(backup_dir.join("stall"), b"").unwrap();
        std::fs::remove_file(backup_dir.join("started")).unwrap();
        let slow_client = client.clone();
        let slow_base = base.clone();
        let slow_cookie = cookie.clone();
        let slow = tokio::spawn(async move {
            slow_client
                .post(format!("{slow_base}/admin/api/ops/backup"))
                .header("cookie", &slow_cookie)
                .send()
                .await
                .unwrap()
        });
        let started = backup_dir.join("started");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !started.exists() {
            assert!(std::time::Instant::now() < deadline, "backup did not start");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let busy = client
            .post(format!("{base}/admin/api/ops/backup"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_api_error(busy, 409, "conflict", "已有备份正在进行").await;
        let timed_out = slow.await.unwrap();
        assert_api_error(timed_out, 504, "timeout", "备份超时").await;
        std::fs::remove_file(backup_dir.join("stall")).unwrap();
        let after = client
            .post(format!("{base}/admin/api/ops/backup"))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(after.status(), 200);
    }

    #[test]
    fn parses_openssl_not_after_formats() {
        let iso = parse_not_after("2027-10-26 18:02:50Z").unwrap();
        assert_eq!(parse_not_after("Oct 26 18:02:50 2027 GMT"), Some(iso));
        assert_eq!(
            parse_not_after("Oct  6 08:01:02 2027 GMT"),
            parse_not_after("2027-10-06 08:01:02Z")
        );
        assert_eq!(parse_not_after("not a date"), None);
    }
}
