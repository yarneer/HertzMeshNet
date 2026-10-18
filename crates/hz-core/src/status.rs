//! Node 的注册状态，是状态机而不是布尔标志。
//! JSON 形状 `{"registered": false}` 是 `hz status` 与 IPC 的稳定契约；
//! 已注册时额外携带注册信息字段。

use serde::{Deserialize, Serialize};

/// 注册成功后 Coordination Server 授予的身份，字段与控制协议的 NodeInfo 对齐。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RegisteredInfo {
    pub node_id: String,
    pub name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub tags: Vec<String>,
    pub owner_user: Option<String>,
    pub expires_at_unix: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeStatus {
    Unregistered,
    Registered(RegisteredInfo),
}

impl Serialize for NodeStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        match self {
            NodeStatus::Unregistered => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("registered", &false)?;
                map.end()
            }
            NodeStatus::Registered(info) => {
                let value = serde_json::to_value(info).map_err(serde::ser::Error::custom)?;
                let object = value.as_object().cloned().unwrap_or_default();
                let mut map = serializer.serialize_map(Some(object.len() + 1))?;
                map.serialize_entry("registered", &true)?;
                for (key, val) in object {
                    map.serialize_entry(&key, &val)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for NodeStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct NodeStatusDto {
            registered: bool,
            #[serde(flatten, default)]
            info: RegisteredInfo,
        }
        let dto = NodeStatusDto::deserialize(deserializer)?;
        if dto.registered {
            Ok(NodeStatus::Registered(dto.info))
        } else {
            Ok(NodeStatus::Unregistered)
        }
    }
}
