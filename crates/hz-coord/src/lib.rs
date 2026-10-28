//! hz-coord：Coordination Server（gRPC + SQLite + 交互式登录 HTTP 面板）。

pub mod addr;
pub mod admin;
pub mod admin_http;
pub mod admin_ui;
pub mod authkey;
pub mod challenge;
pub mod cli;
pub mod health;
pub mod http;
pub mod login;
pub mod map_stream;
pub mod metrics;
pub mod name;
pub mod oidc;
pub mod policy;
pub mod service;
pub mod store;
