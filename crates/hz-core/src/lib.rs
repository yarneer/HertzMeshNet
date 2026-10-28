//! hz-core：`hzd` 与 `hz` 共享的领域类型、本地 IPC 与 Node 侧控制面客户端。

pub mod coord_client;
pub mod dns;
pub mod endpoint;
pub mod ipc;
pub mod keys;
pub mod map;
pub mod netcheck;
pub mod netif;
pub mod netwatch;
#[cfg(target_os = "macos")]
pub mod netwatch_mac;
pub mod outer_dns;
pub mod path;
pub mod paths;
pub mod policy;
pub mod punch;
pub mod relay_client;
pub mod status;
pub mod stun;
pub mod tun;
pub mod version;
pub mod wire;
