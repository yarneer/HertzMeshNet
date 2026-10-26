//! Admin Console 的静态壳，编进 `hz-coord`，没有前端构建。
//!
//! `/admin/` 与 `/admin` 返回 [`index`]。样式和脚本是
//! `/admin/console.css`、`/admin/console.js`。登录门禁在 [`crate::admin_http`]。

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

const INDEX: &str = include_str!("index.html");
const CSS: &str = include_str!("console.css");
const JS: &str = include_str!("console.js");

pub(crate) fn index() -> Response {
    asset("text/html; charset=utf-8", INDEX)
}

pub(crate) fn css() -> Response {
    asset("text/css; charset=utf-8", CSS)
}

pub(crate) fn js() -> Response {
    asset("text/javascript; charset=utf-8", JS)
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}
