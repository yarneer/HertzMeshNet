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
    /// 生效 IPv4 段与段内 DNS 应答地址（#20）：随注册/登录响应获得并随
    /// registration.json 持久化，hzd 以此配置 TUN 路由与本地 DNS，
    /// 替代易失配的 HZD_V4_CIDR 环境变量。旧服务端不带这两个字段。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_cidr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_v4: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeStatus {
    Unregistered,
    Registered(RegisteredInfo),
    /// 归属 User 的 Node 已过有效期（FR-3）：身份与密钥仍在，重新登录即恢复。
    Expired(RegisteredInfo),
}

impl NodeStatus {
    /// 已注册或已过期都持有注册身份；区分只影响提示文案。
    pub fn info(&self) -> Option<&RegisteredInfo> {
        match self {
            NodeStatus::Unregistered => None,
            NodeStatus::Registered(info) | NodeStatus::Expired(info) => Some(info),
        }
    }
}

impl Serialize for NodeStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let (registered, expired, info) = match self {
            NodeStatus::Unregistered => (false, false, None),
            NodeStatus::Registered(info) => (true, false, Some(info)),
            NodeStatus::Expired(info) => (false, true, Some(info)),
        };
        let identity = info
            .map(|info| serde_json::to_value(info).map_err(serde::ser::Error::custom))
            .transpose()?
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        let mut map = serializer.serialize_map(Some(identity.len() + 2))?;
        map.serialize_entry("registered", &registered)?;
        // expired 只在过期态出现：Unregistered/Registered 的 JSON 形状是稳定契约。
        if expired {
            map.serialize_entry("expired", &expired)?;
        }
        for (key, val) in identity {
            map.serialize_entry(&key, &val)?;
        }
        map.end()
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
            #[serde(default)]
            expired: bool,
            #[serde(flatten, default)]
            info: RegisteredInfo,
        }
        let dto = NodeStatusDto::deserialize(deserializer)?;
        if dto.registered {
            Ok(NodeStatus::Registered(dto.info))
        } else if dto.expired {
            Ok(NodeStatus::Expired(dto.info))
        } else {
            Ok(NodeStatus::Unregistered)
        }
    }
}
