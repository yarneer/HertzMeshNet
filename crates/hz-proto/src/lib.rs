//! HzNet 控制协议：protobuf 定义 + tonic 生成代码。
//!
//! 协议版本策略是 N-2：服务端必须接受 >= [`MIN_SUPPORTED_PROTOCOL_VERSION`]
//! 的版本，更旧的客户端被拒绝并收到升级提示。PROTOCOL_VERSION 低于 3 时，
//! 版本 0 从未发布过，最低支持版本保持在 1。

/// 当前服务端实现的协议版本。
pub const PROTOCOL_VERSION: u32 = 1;

/// 服务端接受的最低协议版本（N-2；版本 0 从未发布，故下限不低于 1）。
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = if PROTOCOL_VERSION >= 3 {
    PROTOCOL_VERSION - 2
} else {
    1
};

tonic::include_proto!("hz.v1");
