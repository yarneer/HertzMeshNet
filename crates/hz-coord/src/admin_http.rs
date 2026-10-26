//! HTTP Admin API（`/admin/api`）与 Admin Console 的 OIDC 会话。
//!
//! 会话只发给 Kanidm `hznet_admins`（[`crate::oidc::UserClaims::is_admin`]，
//! 与 GLOSSARY 的 Admin 是同一件事）。没有第二套管理员口令。
//! Node / Auth Key / Policy / 健康 / 备份 REST 加在 [`api_router`]，外层门禁
//! 已经挡住没有会话的请求。浏览器壳在 [`browser_entry`]（静态文件见
//! [`crate::admin_ui`]）：未登录走重定向，`/admin/api` 走 JSON 401。领域逻辑
//! 仍用 [`crate::admin`]，不在这里复制。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Extension, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};

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
    message: &'static str,
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

fn api_error(status: StatusCode, error: &'static str, message: &'static str) -> Response {
    json_response(status, &ApiError { error, message })
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
        let state = Arc::new(HttpState {
            oidc,
            logins: Arc::new(LoginRegistry::new()),
            store,
            login_node_ttl_secs: 90 * 86_400,
            dist: None,
            admin: AdminGate::default(),
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

        let post = client
            .post(format!("{base}/admin/api/me"))
            .send()
            .await
            .unwrap();
        assert_api_error(post, 401, UNAUTHENTICATED, UNAUTHENTICATED_MESSAGE).await;

        let missing = client
            .get(format!("{base}/admin/api/no-such"))
            .send()
            .await
            .unwrap();
        assert_api_error(missing, 401, UNAUTHENTICATED, UNAUTHENTICATED_MESSAGE).await;

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
            "<p>即将就绪</p>",
            "/admin/console.css",
            "/admin/console.js",
        ] {
            assert!(html.contains(needle), "{needle} missing");
        }
        assert_eq!(html.matches("<p>即将就绪</p>").count(), 5);

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
        assert!(
            js.text()
                .await
                .unwrap()
                .contains("fetch(\"/admin/api/me\")")
        );

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
}
