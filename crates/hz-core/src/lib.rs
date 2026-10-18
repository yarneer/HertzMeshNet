//! hz-core：`hzd` 与 `hz` 共享的领域类型、本地 IPC 与 Node 侧控制面客户端。

pub mod coord_client;
pub mod ipc;
pub mod keys;
pub mod netif;
pub mod paths;
pub mod status;
pub mod tun;
pub mod wire;
