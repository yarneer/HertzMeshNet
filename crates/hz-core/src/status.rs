//! Node 的注册状态，是状态机而不是布尔标志。
//! JSON 形状 `{"registered": false}` 是 `hz status` 与 IPC 的稳定契约。

use serde::{Deserialize, Serialize};

/// 注册信息占位：Node Address、Node Name、有效期等由注册票据填充。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredInfo {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "NodeStatusDto", from = "NodeStatusDto")]
pub enum NodeStatus {
    Unregistered,
    Registered(RegisteredInfo),
}

#[derive(Debug, Serialize, Deserialize)]
struct NodeStatusDto {
    registered: bool,
    #[serde(flatten, default)]
    info: RegisteredInfo,
}

impl From<NodeStatus> for NodeStatusDto {
    fn from(status: NodeStatus) -> Self {
        match status {
            NodeStatus::Unregistered => Self {
                registered: false,
                info: RegisteredInfo::default(),
            },
            NodeStatus::Registered(info) => Self {
                registered: true,
                info,
            },
        }
    }
}

impl From<NodeStatusDto> for NodeStatus {
    fn from(dto: NodeStatusDto) -> Self {
        if dto.registered {
            NodeStatus::Registered(dto.info)
        } else {
            NodeStatus::Unregistered
        }
    }
}
