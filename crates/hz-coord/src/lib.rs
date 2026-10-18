//! hz-coord：Coordination Server（gRPC + SQLite + 交互式登录 HTTP 面板）。

pub mod addr;
pub mod authkey;
pub mod challenge;
pub mod cli;
pub mod http;
pub mod login;
pub mod name;
pub mod oidc;
pub mod service;
pub mod store;
