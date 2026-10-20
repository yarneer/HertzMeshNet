//! Coordination Server 的最小 HTTP 面板：交互式登录的 /oidc/start 与
//! /oidc/callback（FR-2），以及分发面（FR-13）`GET /install.sh`、
//! `GET /dl/manifest.json`、`GET /dl/<os>-<arch>/{hzd,hz}`。回调是 OIDC
//! 客户端的一部分，所以落在 Coordination Server 而不是任何 Node。测试走
//! loopback http；生产 TLS 由部署侧（反代或证书配置）负责，与 gRPC 面
//! 的 TLS 同级。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::authkey;
use crate::login::{LoginRegistry, TakeError};
use crate::oidc::OidcClient;
use crate::store::Store;

/// install.sh 里的占位符：serve 时替换成 --public-url / --public-grpc-addr。
const PLACEHOLDER_HTTP_URL: &str = "@@HZNET_COORD_URL@@";
const PLACEHOLDER_GRPC_ADDR: &str = "@@HZNET_COORD_GRPC_ADDR@@";

/// 支持的分发平台（FR-13）：同时也是 /dl 路径的白名单。
pub const DIST_PLATFORMS: [&str; 3] = ["linux-x86_64", "linux-aarch64", "darwin-arm64"];
/// 每个平台分发的二进制。
pub const DIST_BINARIES: [&str; 2] = ["hzd", "hz"];

/// 回调与登录页共用的服务端状态。
pub struct HttpState {
    /// None 表示这台服务器只开了分发面（--dist-dir），交互式登录不可用。
    pub oidc: Option<OidcClient>,
    pub logins: Arc<LoginRegistry>,
    pub store: Store,
    /// 交互式登录授予的 Node 有效期（FR-3 默认 90 天，测试注入更短值）。
    pub login_node_ttl_secs: i64,
    pub dist: Option<Arc<DistState>>,
}

/// serve 启动参数里的分发配置；DistState 是它扫描产物。
pub struct DistConfig {
    /// 目录布局 `<dir>/<os>-<arch>/{hzd,hz}`
    pub dir: PathBuf,
    /// install.sh 里写入的公共 HTTP 基地址（下载 install.sh 用的那个地址）。
    pub public_url: String,
    /// install.sh 写进 HZD_COORD_ADDR 的 gRPC 公网地址。
    pub public_grpc_addr: String,
}

/// 分发面状态：启动时对目录里全部平台二进制做一次 sha256，manifest 常驻内存。
pub struct DistState {
    dir: PathBuf,
    manifest_json: String,
    install_sh_template: String,
    public_url: String,
    public_grpc_addr: String,
}

impl DistState {
    pub fn build(config: &DistConfig) -> anyhow::Result<Self> {
        if !config.dir.is_dir() {
            anyhow::bail!(
                "分发目录 {} 不存在（期望布局 <dir>/<os>-<arch>/{{hzd,hz}}）",
                config.dir.display()
            );
        }
        let mut files = serde_json::Map::new();
        for platform in DIST_PLATFORMS {
            for name in DIST_BINARIES {
                let path = config.dir.join(platform).join(name);
                if let Ok(bytes) = std::fs::read(&path) {
                    let digest = authkey::hex(&Sha256::digest(&bytes));
                    files.insert(
                        format!("{platform}/{name}"),
                        serde_json::json!({ "sha256": digest, "size": bytes.len() }),
                    );
                }
            }
        }
        if files.is_empty() {
            anyhow::bail!(
                "分发目录 {} 里没有任何 <os>-<arch>/{{hzd,hz}} 二进制",
                config.dir.display()
            );
        }
        let manifest = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "files": serde_json::Value::Object(files),
        });
        tracing::info!(
            dir = %config.dir.display(),
            files = manifest["files"].as_object().map(|f| f.len()).unwrap_or(0),
            "dist manifest built"
        );
        Ok(Self {
            dir: config.dir.clone(),
            // 紧凑单行格式；install.sh 用 sed 逐条提取 sha256。
            manifest_json: serde_json::to_string(&manifest)?,
            install_sh_template: include_str!("../../../packaging/install.sh").to_string(),
            public_url: config.public_url.clone(),
            public_grpc_addr: config.public_grpc_addr.clone(),
        })
    }

    /// 替换占位符后的 install.sh；public_url 为空时替换成空串，
    /// 由脚本自身的地址校验兜底报错。
    fn install_sh(&self) -> String {
        self.install_sh_template
            .replace(PLACEHOLDER_HTTP_URL, &self.public_url)
            .replace(PLACEHOLDER_GRPC_ADDR, &self.public_grpc_addr)
    }
}

pub struct HttpHandle {
    pub local_addr: SocketAddr,
    shutdown: tokio::sync::watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

impl HttpHandle {
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub async fn terminated(self) {
        let _ = self.join.await;
    }
}

pub async fn serve_http(listen: SocketAddr, state: Arc<HttpState>) -> anyhow::Result<HttpHandle> {
    let app = Router::new()
        .route("/oidc/start/{login_id}", get(start))
        .route("/oidc/callback", get(callback))
        .route("/install.sh", get(install_sh))
        .route("/dl/manifest.json", get(dl_manifest))
        .route("/dl/{platform}/{binary}", get(dl_binary))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let local_addr = listener.local_addr()?;
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let join = tokio::spawn(async move {
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await;
        if let Err(error) = result {
            tracing::error!(%error, "coord http server exited with error");
        }
    });
    tracing::info!(%local_addr, "coord http server listening");
    Ok(HttpHandle {
        local_addr,
        shutdown: shutdown_tx,
        join,
    })
}

fn take_error_page(error: TakeError) -> Response {
    match error {
        TakeError::NotFound => Html(
            "<h1>登录链接不存在或已被使用</h1><p>请回到该设备重新执行 hz login（已加入 HzNet）或 hz up（尚未加入）生成新的登录链接。</p>",
        )
        .into_response(),
        TakeError::Expired => {
            Html("<h1>登录链接已过期</h1><p>请回到该设备重新执行 hz login（已加入 HzNet）或 hz up（尚未加入）生成新的登录链接。</p>")
                .into_response()
        }
        TakeError::AlreadyUsed => {
            Html("<h1>该登录链接已被使用</h1><p>一次性链接不可重复使用，请回到该设备重新执行 hz login（已加入 HzNet）或 hz up（尚未加入）。</p>")
                .into_response()
        }
    }
}

/// User 在另一台设备打开登录链接：校验 PendingLogin 后跳到 IdP 授权页。
async fn start(State(state): State<Arc<HttpState>>, Path(login_id): Path<String>) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return error_page("此服务器未配置交互式登录（OIDC），无法打开登录链接");
    };
    let (nonce, verifier) = match state.logins.authorize_material(&login_id) {
        Ok(material) => material,
        Err(error) => {
            tracing::warn!(%login_id, ?error, "oidc start rejected");
            return take_error_page(error);
        }
    };
    // state 承载 login_id：回调据此找回同一份 PendingLogin 与它的 PKCE verifier。
    let request = oidc.authorization_request(&login_id, &nonce, &verifier);
    tracing::info!(%login_id, "oidc authorization redirect issued");
    Redirect::temporary(request.url.as_str()).into_response()
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// IdP 回调：换令牌、校验 nonce、落 User 与 Node 绑定，然后给浏览器一个结果页。
async fn callback(
    State(state): State<Arc<HttpState>>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return error_page("此服务器未配置交互式登录（OIDC），回调无效");
    };
    if let Some(error) = query.error {
        let description = query.error_description.unwrap_or_default();
        tracing::warn!(%error, %description, "oidc callback received error");
        if let Some(login_id) = query.state {
            state
                .logins
                .fail(&login_id, format!("IdP 返回错误 {error}：{description}"));
        }
        return error_page(&format!("身份提供方返回错误：{error}"));
    }
    let (Some(code), Some(login_id)) = (query.code, query.state) else {
        return (StatusCode::BAD_REQUEST, "回调缺少 code 或 state").into_response();
    };

    let material = match state.logins.take_for_callback(&login_id) {
        Ok(material) => material,
        Err(error) => {
            tracing::warn!(%login_id, ?error, "oidc callback rejected");
            return take_error_page(error);
        }
    };

    let claims = match oidc
        .exchange(&code, &material.pkce_verifier, &material.nonce)
        .await
    {
        Ok(claims) => claims,
        Err(error) => {
            tracing::error!(%login_id, %error, "oidc token exchange failed");
            state.logins.fail(&login_id, format!("{error:#}"));
            return error_page("登录失败：与身份提供方的通信未完成，请重新发起登录");
        }
    };

    let expires_at_unix = crate::store::unix_now() + state.login_node_ttl_secs;
    let bind = async {
        let user_id = state
            .store
            .upsert_user(&claims.preferred_username, claims.is_admin())
            .await?;
        state
            .store
            .bind_node_to_user(
                &material.machine_key_pub,
                &material.node_key_pub,
                &material.hostname,
                &user_id,
                expires_at_unix,
            )
            .await
    };
    match bind.await {
        Ok(record) => {
            state.logins.complete(&login_id, record.clone());
            tracing::info!(node_id = %record.id, owner = ?record.owner_user, "interactive login completed");
            Html(format!(
                "<h1>登录成功</h1><p>Node {} 已加入 HzNet 并归属该账号，返回服务器查看即可。</p>",
                record.name
            ))
            .into_response()
        }
        Err(error) => {
            tracing::error!(%login_id, %error, "bind node after login failed");
            state.logins.fail(&login_id, "服务端存储错误".to_string());
            error_page("登录失败：服务端存储错误，请稍后重试")
        }
    }
}

fn error_page(message: &str) -> Response {
    Html(format!("<h1>登录失败</h1><p>{message}</p>")).into_response()
}

async fn install_sh(State(state): State<Arc<HttpState>>) -> Response {
    let Some(dist) = state.dist.as_ref() else {
        return not_found();
    };
    (
        [(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")],
        dist.install_sh(),
    )
        .into_response()
}

async fn dl_manifest(State(state): State<Arc<HttpState>>) -> Response {
    let Some(dist) = state.dist.as_ref() else {
        return not_found();
    };
    (
        [(header::CONTENT_TYPE, "application/json")],
        dist.manifest_json.clone(),
    )
        .into_response()
}

/// 平台与二进制名只认白名单，路径拼接因此不可能逃出 dist 目录。
async fn dl_binary(
    State(state): State<Arc<HttpState>>,
    Path((platform, binary)): Path<(String, String)>,
) -> Response {
    let Some(dist) = state.dist.as_ref() else {
        return not_found();
    };
    if !DIST_PLATFORMS.contains(&platform.as_str()) || !DIST_BINARIES.contains(&binary.as_str()) {
        return not_found();
    }
    match tokio::fs::read(dist.dir.join(&platform).join(&binary)).await {
        Ok(bytes) => ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response(),
        Err(error) => {
            tracing::warn!(%platform, %binary, %error, "dist binary missing");
            not_found()
        }
    }
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}
