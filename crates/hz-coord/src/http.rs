//! Coordination Server 的最小 HTTP 面板：交互式登录的 /oidc/start 与
//! /oidc/callback（FR-2）。回调是 OIDC 客户端的一部分，所以落在 Coordination
//! Server 而不是任何 Node。测试走 loopback http；生产 TLS 由部署侧（反代或
//! 证书配置）负责，与 gRPC 面的 TLS 同级。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use serde::Deserialize;

use crate::login::{LoginRegistry, TakeError};
use crate::oidc::OidcClient;
use crate::store::Store;

/// 回调与登录页共用的服务端状态。
pub struct HttpState {
    pub oidc: OidcClient,
    pub logins: Arc<LoginRegistry>,
    pub store: Store,
    /// 交互式登录授予的 Node 有效期（FR-3 默认 90 天，测试注入更短值）。
    pub login_node_ttl_secs: i64,
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
            "<h1>登录链接不存在或已被使用</h1><p>请回到服务器重新执行 hz up 生成新的登录链接。</p>",
        )
        .into_response(),
        TakeError::Expired => {
            Html("<h1>登录链接已过期</h1><p>请回到服务器重新执行 hz up 生成新的登录链接。</p>")
                .into_response()
        }
        TakeError::AlreadyUsed => {
            Html("<h1>该登录链接已被使用</h1><p>一次性链接不可重复使用，请重新执行 hz up。</p>")
                .into_response()
        }
    }
}

/// User 在另一台设备打开登录链接：校验 PendingLogin 后跳到 IdP 授权页。
async fn start(State(state): State<Arc<HttpState>>, Path(login_id): Path<String>) -> Response {
    let (nonce, verifier) = match state.logins.authorize_material(&login_id) {
        Ok(material) => material,
        Err(error) => {
            tracing::warn!(%login_id, ?error, "oidc start rejected");
            return take_error_page(error);
        }
    };
    // state 承载 login_id：回调据此找回同一份 PendingLogin 与它的 PKCE verifier。
    let request = state
        .oidc
        .authorization_request(&login_id, &nonce, &verifier);
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

    let claims = match state
        .oidc
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
