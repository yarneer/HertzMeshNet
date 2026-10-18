//! Node 侧 Network Map 本地缓存（FR-6）。结构是 reducer 而不是散落的 if：
//! 全量（apply_full）与增量（apply_delta）都归结为对同一张 node_id 主键表的
//! 归并，返回本次变化供装配层增量重配数据面；每次变化原子落盘
//! network-map.json（0600，写临时文件后改名），Coordination Server 不可达的
//! 重启场景从这份文件恢复对端视图。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// 缓存文件名（位于状态目录）。
pub const CACHE_FILE: &str = "network-map.json";

/// Network Map 里的一个 Node 条目：协议 NodeInfo 的领域形态，
/// 可直接序列化持久化，装配层与 `hz status` 都从它取数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapNode {
    pub node_id: String,
    pub name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub tags: Vec<String>,
    pub owner_user: Option<String>,
    pub expires_at_unix: Option<i64>,
    pub node_key_pub: Vec<u8>,
    pub endpoints: Vec<String>,
    /// 按来源区分的 Endpoint（FR-8）；旧缓存文件没有该字段时按空装载。
    #[serde(default)]
    pub detailed_endpoints: Vec<DetailedEndpoint>,
}

/// 一个带来源的 Endpoint：addr 是 "ip:port"，kind ∈ lan/stun/v6。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetailedEndpoint {
    pub addr: String,
    pub kind: String,
}

impl DetailedEndpoint {
    pub fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        self.addr.parse().ok()
    }

    pub fn kind(&self) -> crate::endpoint::EndpointKind {
        crate::endpoint::EndpointKind::parse(&self.kind)
            .unwrap_or(crate::endpoint::EndpointKind::Lan)
    }
}

impl From<hz_proto::NodeInfo> for MapNode {
    fn from(node: hz_proto::NodeInfo) -> Self {
        let detailed_endpoints = node
            .detailed_endpoints
            .iter()
            .filter_map(|endpoint| {
                let ip: std::net::IpAddr = endpoint.addr.parse().ok()?;
                let kind = hz_proto::EndpointKind::try_from(endpoint.kind).ok()?;
                Some(DetailedEndpoint {
                    addr: std::net::SocketAddr::new(ip, endpoint.port as u16).to_string(),
                    kind: match kind {
                        hz_proto::EndpointKind::Stun => "stun",
                        hz_proto::EndpointKind::V6 => "v6",
                        _ => "lan",
                    }
                    .to_string(),
                })
            })
            .collect();
        Self {
            node_id: node.node_id,
            name: node.name,
            ipv4: node.ipv4,
            ipv6: node.ipv6,
            tags: node.tags,
            owner_user: node.owner_user,
            expires_at_unix: node.expires_at_unix,
            node_key_pub: node.node_key_pub,
            endpoints: node.endpoints,
            detailed_endpoints,
        }
    }
}

/// 一次 Map 更新带来的变化；等价于协议里的 MapDelta。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MapChange {
    pub added_or_updated: Vec<MapNode>,
    pub removed_node_ids: Vec<String>,
}

impl MapChange {
    pub fn is_empty(&self) -> bool {
        self.added_or_updated.is_empty() && self.removed_node_ids.is_empty()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheFile {
    version: u64,
    nodes: Vec<MapNode>,
}

struct CacheState {
    nodes: BTreeMap<String, MapNode>,
    version: u64,
    dirty: bool,
}

/// 进程内共享的本地 Network Map 缓存；读侧拿快照，写侧只有 Map 消费任务。
pub struct NetworkMapCache {
    state_dir: PathBuf,
    state: Mutex<CacheState>,
}

impl NetworkMapCache {
    /// 不读盘的空缓存；磁盘内容损坏时的安全退路。
    pub fn empty(state_dir: &Path) -> Self {
        Self {
            state_dir: state_dir.to_path_buf(),
            state: Mutex::new(CacheState {
                nodes: BTreeMap::new(),
                version: 0,
                dirty: false,
            }),
        }
    }

    /// 从状态目录装载缓存；文件不存在视为空缓存（首次运行）。
    pub fn load(state_dir: &Path) -> anyhow::Result<Self> {
        let path = state_dir.join(CACHE_FILE);
        let file: CacheFile = match std::fs::read_to_string(&path) {
            Ok(text) => {
                serde_json::from_str(&text).with_context(|| format!("解析 {path:?} 失败"))?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => CacheFile::default(),
            Err(error) => {
                return Err(error).with_context(|| format!("读取 {path:?} 失败"));
            }
        };
        let nodes = file
            .nodes
            .into_iter()
            .map(|node| (node.node_id.clone(), node))
            .collect();
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            state: Mutex::new(CacheState {
                nodes,
                version: file.version,
                dirty: false,
            }),
        })
    }

    /// 全量快照归并：不在新快照里的对端被移除。
    pub fn apply_full(&self, nodes: Vec<MapNode>) -> MapChange {
        let fresh = nodes
            .into_iter()
            .map(|node| (node.node_id.clone(), node))
            .collect::<BTreeMap<_, _>>();
        self.reduce(|state| {
            let removed_node_ids = state
                .nodes
                .keys()
                .filter(|id| !fresh.contains_key(*id))
                .cloned()
                .collect::<Vec<_>>();
            let added_or_updated = fresh
                .values()
                .filter(|node| state.nodes.get(&node.node_id) != Some(node))
                .cloned()
                .collect::<Vec<_>>();
            state.nodes = fresh;
            MapChange {
                added_or_updated,
                removed_node_ids,
            }
        })
    }

    /// 增量归并：added_or_updated 覆盖同 id 条目，removed 按 id 移除（不存在的 id 是空操作）。
    pub fn apply_delta(
        &self,
        added_or_updated: Vec<MapNode>,
        removed_node_ids: Vec<String>,
    ) -> MapChange {
        self.reduce(|state| {
            let mut merged = Vec::new();
            for node in added_or_updated {
                if state.nodes.get(&node.node_id) != Some(&node) {
                    state.nodes.insert(node.node_id.clone(), node.clone());
                    merged.push(node);
                }
            }
            let removed = removed_node_ids
                .into_iter()
                .filter(|id| state.nodes.remove(id).is_some())
                .collect::<Vec<_>>();
            MapChange {
                added_or_updated: merged,
                removed_node_ids: removed,
            }
        })
    }

    /// 当前快照（按 node_id 排序的不可变副本）。
    pub fn snapshot(&self) -> Vec<MapNode> {
        self.state
            .lock()
            .expect("map cache poisoned")
            .nodes
            .values()
            .cloned()
            .collect()
    }

    /// 单调递增的版本号；每次实际变化加一。
    pub fn version(&self) -> u64 {
        self.state.lock().expect("map cache poisoned").version
    }

    fn reduce(&self, mutate: impl FnOnce(&mut CacheState) -> MapChange) -> MapChange {
        let mut state = self.state.lock().expect("map cache poisoned");
        let change = mutate(&mut state);
        if change.is_empty() {
            return change;
        }
        state.version += 1;
        state.dirty = true;
        drop(state);
        // 落盘失败不回退内存视图：数据面照常工作，日志里可见。
        if let Err(error) = self.persist() {
            tracing::error!(%error, "persist network map cache failed");
        }
        change
    }

    /// 原子写：临时文件 0600 → rename。内容未变化时跳过。
    fn persist(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().expect("map cache poisoned");
        if !state.dirty {
            return Ok(());
        }
        let file = CacheFile {
            version: state.version,
            nodes: state.nodes.values().cloned().collect(),
        };
        std::fs::create_dir_all(&self.state_dir)?;
        let path = self.state_dir.join(CACHE_FILE);
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut handle = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            handle.write_all(serde_json::to_string(&file)?.as_bytes())?;
        }
        std::fs::rename(&tmp, &path)?;
        state.dirty = false;
        Ok(())
    }
}
