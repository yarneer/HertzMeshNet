//! SQLite 存储（sqlx 0.8，运行时查询，无编译期宏依赖）：迁移、Auth Key 消费、
//! Node 注册（地址与名字在同一事务内分配）。

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use rand_core::{OsRng, RngCore};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};

use crate::addr::{AddressConfig, ula_ipv6};
use crate::authkey;
use crate::name::NodeName;

const META_ULA_PREFIX: &str = "ula_prefix";
const META_RELAY_TOKEN_HASH: &str = "relay_token_hash";
const META_POLICY_CURRENT_VERSION: &str = "policy_current_version";

#[derive(Debug, thiserror::Error)]
pub enum AuthKeyError {
    #[error("Auth Key 无效")]
    Invalid,
    #[error("Auth Key 已过期")]
    Expired,
    #[error("Auth Key 已使用")]
    AlreadyUsed,
}

/// 注册成功后返回的 Node 记录，字段与 NodeInfo 一一对应。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRecord {
    pub id: String,
    pub name: String,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    pub tags: Vec<String>,
    pub owner_user: Option<String>,
    pub expires_at_unix: Option<i64>,
    pub node_key_pub: Vec<u8>,
    /// 该 Node 上报的 UDP Endpoint 及来源（lan/stun/v6）。
    pub udp_endpoints: Vec<StoredEndpoint>,
}

/// 落库形态的 Endpoint：udp_endpoints 列的 JSON 元素。
/// 旧库里的纯字符串元素按 lan 来源装载（#8 之前的唯一来源）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredEndpoint {
    pub addr: String,
    pub kind: String,
}

impl StoredEndpoint {
    pub fn lan(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            kind: "lan".to_string(),
        }
    }

    /// 未知来源的兜底种类：按 lan 对待。
    pub fn of_kind(addr: impl Into<String>, kind: &str) -> Self {
        let known = matches!(kind, "lan" | "stun" | "v6");
        Self {
            addr: addr.into(),
            kind: if known {
                kind.to_string()
            } else {
                "lan".to_string()
            },
        }
    }

    #[cfg(test)]
    pub fn addr_only(&self) -> String {
        self.addr.clone()
    }
}

fn parse_stored_endpoints(json: &str) -> anyhow::Result<Vec<StoredEndpoint>> {
    let values: Vec<serde_json::Value> = serde_json::from_str(json)
        .map_err(|e| anyhow::anyhow!("invalid udp_endpoints in db: {e}"))?;
    values
        .into_iter()
        .map(|value| match value {
            serde_json::Value::String(addr) => Ok(StoredEndpoint::lan(addr)),
            serde_json::Value::Object(fields) => {
                let addr = fields
                    .get("addr")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("udp_endpoints 元素缺少 addr 字段"))?;
                let kind = fields.get("kind").and_then(|v| v.as_str()).unwrap_or("lan");
                Ok(StoredEndpoint::of_kind(addr, kind))
            }
            _ => Err(anyhow::anyhow!("udp_endpoints 元素既非字符串也非对象")),
        })
        .collect()
}

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
    addr: AddressConfig,
    /// 影响 Network Map 的变更信号；注册/Endpoint/吊销路径提交后递增，
    /// 推送任务在其上等待并计算差量。
    changes: tokio::sync::watch::Sender<u64>,
    /// 测试临时目录（[`Store::open_in_memory`]）；随最后一个克隆存活。
    #[allow(dead_code)]
    temp: Option<std::sync::Arc<tempfile::TempDir>>,
}

impl Store {
    /// 打开（必要时创建）文件库：WAL + 外键，启动即迁移。
    pub async fn open(db_path: &Path, addr: AddressConfig) -> anyhow::Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(db_path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;
        Self::from_pool(pool, addr).await
    }

    /// 测试用库：临时文件承载（不是 `sqlite::memory:`）。文件库在连接被
    /// 摧毁后重建仍读到同一份数据；内存库则会变成空库——fan-out 任务被
    /// abort 时可能正持有唯一连接，那之后的任何查询都会失败。
    /// PRAGMA 与 [`Store::open`] 完全一致（WAL + 外键）：测试库必须复现
    /// 生产库的并发行为，而不是只复现表结构。
    pub async fn open_in_memory(addr: AddressConfig) -> anyhow::Result<Self> {
        let dir = tempfile::tempdir()?;
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(dir.path().join("test.db"))
                    .create_if_missing(true)
                    .journal_mode(SqliteJournalMode::Wal)
                    .synchronous(SqliteSynchronous::Normal)
                    .foreign_keys(true),
            )
            .await?;
        let store = Self::from_pool(pool, addr).await?;
        Ok(Self {
            pool: store.pool,
            addr: store.addr,
            changes: store.changes,
            temp: Some(std::sync::Arc::new(dir)),
        })
    }

    /// 写事务从这里开始：BEGIN IMMEDIATE 在第一条语句前取写锁，锁冲突
    /// 都是可以等 busy_timeout 的普通 BUSY。DEFERRED 事务先读后写时，
    /// 若别的事务在读快照之后提交了写入，升级会立刻得到不可等待的
    /// BUSY_SNAPSHOT（code 5/517，busy handler 不介入）——并发注册与
    /// Endpoint 上报同帧到达时在慢机器上可稳定复现。
    async fn begin_write(&self) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>, sqlx::Error> {
        self.pool.begin_with("BEGIN IMMEDIATE").await
    }

    pub async fn from_pool(pool: SqlitePool, addr: AddressConfig) -> anyhow::Result<Self> {
        sqlx::migrate!("./migrations").run(&pool).await?;
        let (changes, _) = tokio::sync::watch::channel(0);
        Ok(Self {
            pool,
            addr,
            changes,
            temp: None,
        })
    }

    /// 订阅 Network Map 相关变更；每次变化 version 递增。
    pub fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }

    fn notify_change(&self) {
        self.changes.send_modify(|version| *version += 1);
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// 签发 Auth Key：明文只在这里产生并返回一次，库里只落哈希。
    pub async fn create_auth_key(
        &self,
        expires_at_unix: i64,
        single_use: bool,
        tags: &[String],
    ) -> anyhow::Result<String> {
        let plaintext = authkey::generate_plaintext();
        let now = unix_now();
        sqlx::query(
            "INSERT INTO auth_keys (id, key_hash, created_at_unix, expires_at_unix, single_use, used_at_unix, tags)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
        )
        .bind(authkey::random_id())
        .bind(authkey::hash(&plaintext))
        .bind(now)
        .bind(expires_at_unix)
        .bind(single_use as i64)
        .bind(serde_json::to_string(tags)?)
        .execute(&self.pool)
        .await?;
        Ok(plaintext)
    }

    /// 校验并消费 Auth Key，成功时返回它预绑定的 Tag。
    pub async fn consume_auth_key(&self, plaintext: &str) -> Result<Vec<String>, AuthKeyError> {
        let key_hash = authkey::hash(plaintext);
        let mut tx = self
            .begin_write()
            .await
            .map_err(|e| store_broken(e, AuthKeyError::Invalid))?;
        let row = sqlx::query(
            "SELECT expires_at_unix, single_use, used_at_unix, tags FROM auth_keys WHERE key_hash = ?1",
        )
        .bind(&key_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| store_broken(e, AuthKeyError::Invalid))?;
        let Some(row) = row else {
            return Err(AuthKeyError::Invalid);
        };
        let expires_at_unix: i64 = row.get("expires_at_unix");
        let single_use: i64 = row.get("single_use");
        let used_at_unix: Option<i64> = row.get("used_at_unix");
        let tags_json: String = row.get("tags");
        if expires_at_unix < unix_now() {
            return Err(AuthKeyError::Expired);
        }
        if single_use != 0 && used_at_unix.is_some() {
            return Err(AuthKeyError::AlreadyUsed);
        }
        if single_use != 0 {
            sqlx::query("UPDATE auth_keys SET used_at_unix = ?1 WHERE key_hash = ?2")
                .bind(unix_now())
                .bind(&key_hash)
                .execute(&mut *tx)
                .await
                .map_err(|e| store_broken(e, AuthKeyError::Invalid))?;
        }
        tx.commit()
            .await
            .map_err(|e| store_broken(e, AuthKeyError::Invalid))?;
        let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
        Ok(tags)
    }

    /// 注册 Node。同一 Machine Key 再次注册是幂等的：身份、地址、名字不变，只更新 Node Key。
    pub async fn register_node(
        &self,
        machine_key_pub: &[u8],
        node_key_pub: &[u8],
        hostname: &str,
        tags: &[String],
        user_id: Option<&str>,
        expires_at_unix: Option<i64>,
    ) -> anyhow::Result<NodeRecord> {
        let mut tx = self.begin_write().await?;

        if let Some(mut existing) = node_by_machine_key(&mut tx, machine_key_pub).await? {
            sqlx::query("UPDATE nodes SET node_key_pub = ?1 WHERE id = ?2")
                .bind(node_key_pub)
                .bind(&existing.id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            // Node Key 变更影响对端（需按新公钥重建会话），必须唤醒推送。
            self.notify_change();
            existing.node_key_pub = node_key_pub.to_vec();
            tracing::info!(node_id = %existing.id, "re-registered existing node");
            return Ok(existing);
        }
        let taken_v4: HashSet<Ipv4Addr> = sqlx::query("SELECT ipv4 FROM nodes")
            .fetch_all(&mut *tx)
            .await?
            .iter()
            .map(|row| parse_v4(&row.get::<String, _>("ipv4")))
            .collect::<anyhow::Result<_>>()?;
        let ipv4 = self
            .addr
            .allocate(&taken_v4)
            .ok_or_else(|| anyhow::anyhow!("地址段 {} 已耗尽，无法注册新 Node", self.addr.cidr))?;

        let base = NodeName::normalize(hostname);
        let name = dedupe_name_in_tx(&mut tx, &base)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Node Name 基名 {base} 的 99 个候选名全部被占用"))?;

        let ula = ensure_ula_prefix(&mut tx).await?;
        let ipv6 = ula_ipv6(ula, ipv4);

        let id = authkey::random_id();
        let now = unix_now();
        sqlx::query(
            "INSERT INTO nodes (id, machine_key_pub, node_key_pub, name, ipv4, ipv6, tags, user_id, expires_at_unix, revoked_at_unix, created_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10)",
        )
        .bind(&id)
        .bind(machine_key_pub)
        .bind(node_key_pub)
        .bind(&name)
        .bind(ipv4.to_string())
        .bind(ipv6.to_string())
        .bind(serde_json::to_string(tags)?)
        .bind(user_id)
        .bind(expires_at_unix)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        self.notify_change();
        let owner_user = match user_id {
            Some(uid) => sqlx::query("SELECT name FROM users WHERE id = ?1")
                .bind(uid)
                .fetch_optional(&self.pool)
                .await?
                .map(|row| row.get::<String, _>("name")),
            None => None,
        };
        Ok(NodeRecord {
            id,
            name,
            ipv4,
            ipv6,
            tags: tags.to_vec(),
            owner_user,
            expires_at_unix,
            node_key_pub: node_key_pub.to_vec(),
            udp_endpoints: Vec::new(),
        })
    }

    /// 上报路径整体覆盖该 Node 的 UDP Endpoint 列表（带来源）。
    pub async fn update_udp_endpoints(
        &self,
        node_id: &str,
        endpoints: &[StoredEndpoint],
    ) -> anyhow::Result<()> {
        sqlx::query("UPDATE nodes SET udp_endpoints = ?1 WHERE id = ?2")
            .bind(serde_json::to_string(endpoints)?)
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        self.notify_change();
        Ok(())
    }

    /// 吊销 Node：之后不再出现在任何 Network Map 里；已在推送流上的对端
    /// 会收到 removed 差量。重复吊销是空操作。返回是否发生了状态迁移。
    pub async fn revoke_node(&self, node_id: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE nodes SET revoked_at_unix = ?1 WHERE id = ?2 AND revoked_at_unix IS NULL",
        )
        .bind(unix_now())
        .bind(node_id)
        .execute(&self.pool)
        .await?;
        let revoked = result.rows_affected() > 0;
        if revoked {
            self.notify_change();
        }
        Ok(revoked)
    }

    /// Network Map 快照：所有未吊销、未过期的 Node（含 Node Key 与 Endpoint）。
    pub async fn network_map(&self) -> anyhow::Result<Vec<NodeRecord>> {
        let rows = sqlx::query(
            "SELECT n.id, n.name, n.ipv4, n.ipv6, n.tags, u.name AS owner_user,
                    n.expires_at_unix, n.node_key_pub, n.udp_endpoints
             FROM nodes n LEFT JOIN users u ON u.id = n.user_id
             WHERE n.revoked_at_unix IS NULL
               AND (n.expires_at_unix IS NULL OR n.expires_at_unix > ?1)",
        )
        .bind(unix_now())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(node_record_from_row).collect()
    }

    /// 按 Machine Key 查未吊销的 Node；StreamNetworkMap 认证用。
    pub async fn node_by_machine_key(
        &self,
        machine_key_pub: &[u8],
    ) -> anyhow::Result<Option<NodeRecord>> {
        let mut tx = self.pool.begin().await?;
        let record = node_by_machine_key(&mut tx, machine_key_pub).await?;
        tx.commit().await?;
        Ok(record)
    }

    /// 签发 Relay Token：明文只在这里产生并返回一次，库里只落 sha256。
    /// 重复签发整体替换旧令牌。
    pub async fn create_relay_token(&self) -> anyhow::Result<String> {
        let plaintext = authkey::generate_relay_token();
        sqlx::query(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(META_RELAY_TOKEN_HASH)
        .bind(authkey::hash(&plaintext))
        .execute(&self.pool)
        .await?;
        Ok(plaintext)
    }

    /// 当前有效的 Relay Token 哈希；未签发过为 None。
    pub async fn relay_token_hash(&self) -> anyhow::Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM meta WHERE key = ?1")
            .bind(META_RELAY_TOKEN_HASH)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| row.get::<String, _>("value")))
    }

    /// 交互式登录的用户落库：名字唯一，重复登录只刷新 Admin 身份（FR-11）。
    /// 返回 user id。
    pub async fn upsert_user(&self, name: &str, is_admin: bool) -> anyhow::Result<String> {
        sqlx::query(
            "INSERT INTO users (id, name, is_admin) VALUES (?1, ?2, ?3)
             ON CONFLICT (name) DO UPDATE SET is_admin = excluded.is_admin",
        )
        .bind(authkey::random_id())
        .bind(name)
        .bind(is_admin as i64)
        .execute(&self.pool)
        .await?;
        let row = sqlx::query("SELECT id FROM users WHERE name = ?1")
            .bind(name)
            .fetch_one(&self.pool)
            .await?;
        tracing::info!(user = name, is_admin, "user upserted via interactive login");
        Ok(row.get("id"))
    }

    /// 交互式登录绑定 Node：新 Machine Key 走注册路径（地址与名字同事务分配）；
    /// 已存在的 Node 保持身份、地址、名字不变，刷新 Node Key、归属与有效期（FR-3）。
    pub async fn bind_node_to_user(
        &self,
        machine_key_pub: &[u8],
        node_key_pub: &[u8],
        hostname: &str,
        user_id: &str,
        expires_at_unix: i64,
    ) -> anyhow::Result<NodeRecord> {
        let mut tx = self.begin_write().await?;
        if let Some(mut existing) = node_by_machine_key(&mut tx, machine_key_pub).await? {
            sqlx::query(
                "UPDATE nodes SET node_key_pub = ?1, user_id = ?2, expires_at_unix = ?3 WHERE id = ?4",
            )
            .bind(node_key_pub)
            .bind(user_id)
            .bind(expires_at_unix)
            .bind(&existing.id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            // 轮换后的 Node Key、归属与有效期都影响 Network Map 内容。
            self.notify_change();
            existing.node_key_pub = node_key_pub.to_vec();
            existing.expires_at_unix = Some(expires_at_unix);
            existing.owner_user = Some(
                sqlx::query("SELECT name FROM users WHERE id = ?1")
                    .bind(user_id)
                    .fetch_one(&self.pool)
                    .await?
                    .get::<String, _>("name"),
            );
            tracing::info!(node_id = %existing.id, "node re-bound by interactive login");
            return Ok(existing);
        }
        drop(tx);

        let record = self
            .register_node(
                machine_key_pub,
                node_key_pub,
                hostname,
                &[],
                Some(user_id),
                Some(expires_at_unix),
            )
            .await?;
        Ok(record)
    }

    // ------------------------------------------------------------------
    // Policy（FR-10）：版本历史 + 当前版本指针。写入路径只管存，
    // 校验（语法 + 引用存在性）在服务层落库前完成。
    // ------------------------------------------------------------------

    /// 入库新版本并指向它；版本号由 AUTOINCREMENT 分配。
    /// 唤醒 Map 推送任务重算每个订阅者的过滤视图。
    pub async fn push_policy(&self, content: &str) -> anyhow::Result<i64> {
        let mut tx = self.begin_write().await?;
        let result =
            sqlx::query("INSERT INTO policy_versions (content, created_at_unix) VALUES (?1, ?2)")
                .bind(content)
                .bind(unix_now())
                .execute(&mut *tx)
                .await?;
        let version = result.last_insert_rowid();
        set_current_policy_version(&mut tx, version).await?;
        tx.commit().await?;
        self.notify_change();
        tracing::info!(version, "policy version stored");
        Ok(version)
    }

    /// 指向一个已存在的版本；内容不变（回滚不产生新版本）。
    pub async fn rollback_policy(&self, version: i64) -> anyhow::Result<()> {
        let exists = sqlx::query("SELECT 1 FROM policy_versions WHERE version = ?1")
            .bind(version)
            .fetch_optional(&self.pool)
            .await?;
        if exists.is_none() {
            anyhow::bail!("版本 {version} 不存在");
        }
        let mut tx = self.begin_write().await?;
        set_current_policy_version(&mut tx, version).await?;
        tx.commit().await?;
        self.notify_change();
        tracing::info!(version, "policy rolled back");
        Ok(())
    }

    /// 当前 Policy 原文与版本号；从未推送过为 None。
    pub async fn current_policy(&self) -> anyhow::Result<Option<(i64, String)>> {
        let Some(version) = self.current_policy_version().await? else {
            return Ok(None);
        };
        let content = self
            .policy_version_content(version)
            .await?
            .ok_or_else(|| anyhow::anyhow!("meta 指向的 Policy 版本 {version} 缺失"))?;
        Ok(Some((version, content)))
    }

    /// 全部历史版本（含当前），按版本号倒序。
    pub async fn policy_history(&self) -> anyhow::Result<Vec<PolicyVersionRow>> {
        let rows = sqlx::query(
            "SELECT version, created_at_unix FROM policy_versions ORDER BY version DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|row| PolicyVersionRow {
                version: row.get("version"),
                created_at_unix: row.get("created_at_unix"),
            })
            .collect())
    }

    pub async fn policy_version_content(&self, version: i64) -> anyhow::Result<Option<String>> {
        let row = sqlx::query("SELECT content FROM policy_versions WHERE version = ?1")
            .bind(version)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| row.get("content")))
    }

    async fn current_policy_version(&self) -> anyhow::Result<Option<i64>> {
        let row = sqlx::query("SELECT value FROM meta WHERE key = ?1")
            .bind(META_POLICY_CURRENT_VERSION)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|row| row.get::<String, _>("value").parse().ok()))
    }

    /// users 表里的全部 User 名（Policy 引用存在性校验用）。
    pub async fn user_names(&self) -> anyhow::Result<HashSet<String>> {
        let rows = sqlx::query("SELECT name FROM users")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(|row| row.get("name")).collect())
    }

    /// 按名字查 Admin 身份；User 不存在为 None。
    pub async fn user_is_admin(&self, name: &str) -> anyhow::Result<Option<bool>> {
        let row = sqlx::query("SELECT is_admin FROM users WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| row.get::<i64, _>("is_admin") != 0))
    }
}

async fn set_current_policy_version(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    version: i64,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(META_POLICY_CURRENT_VERSION)
    .bind(version.to_string())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 历史版本条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVersionRow {
    pub version: i64,
    pub created_at_unix: i64,
}

fn store_broken(error: sqlx::Error, fallback: AuthKeyError) -> AuthKeyError {
    tracing::error!(%error, "sqlite failure while consuming auth key");
    fallback
}

async fn node_by_machine_key(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    machine_key_pub: &[u8],
) -> anyhow::Result<Option<NodeRecord>> {
    let row = sqlx::query(
        "SELECT n.id, n.name, n.ipv4, n.ipv6, n.tags, u.name AS owner_user,
                n.expires_at_unix, n.node_key_pub, n.udp_endpoints
         FROM nodes n LEFT JOIN users u ON u.id = n.user_id
         WHERE n.machine_key_pub = ?1 AND n.revoked_at_unix IS NULL",
    )
    .bind(machine_key_pub)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| node_record_from_row(&row)).transpose()
}

fn node_record_from_row(row: &sqlx::sqlite::SqliteRow) -> anyhow::Result<NodeRecord> {
    Ok(NodeRecord {
        id: row.get("id"),
        name: row.get("name"),
        ipv4: parse_v4(&row.get::<String, _>("ipv4"))?,
        ipv6: row
            .get::<String, _>("ipv6")
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid ipv6 in db: {e}"))?,
        tags: serde_json::from_str(&row.get::<String, _>("tags")).unwrap_or_default(),
        owner_user: row.try_get("owner_user").ok().flatten(),
        expires_at_unix: row.get("expires_at_unix"),
        node_key_pub: row.get("node_key_pub"),
        udp_endpoints: parse_stored_endpoints(&row.get::<String, _>("udp_endpoints"))?,
    })
}

/// Node Name 去重必须与插入同事务，逐候选名查询。
async fn dedupe_name_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    base: &str,
) -> anyhow::Result<Option<String>> {
    let mut candidates = vec![base.to_string()];
    for n in 2..=99u32 {
        candidates.push(format!("{base}-{n}"));
    }
    for candidate in candidates {
        let taken = sqlx::query("SELECT 1 AS taken FROM nodes WHERE name = ?1")
            .bind(&candidate)
            .fetch_optional(&mut **tx)
            .await?;
        if taken.is_none() {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// 首次需要 ULA 时生成 fd 开头的 /48 前缀并写入 meta；已有则复用。
async fn ensure_ula_prefix(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> anyhow::Result<[u8; 6]> {
    if let Some(existing) = sqlx::query("SELECT value FROM meta WHERE key = ?1")
        .bind(META_ULA_PREFIX)
        .fetch_optional(&mut **tx)
        .await?
    {
        return parse_ula(&existing.get::<String, _>("value"));
    }
    let mut prefix = [0u8; 6];
    OsRng.fill_bytes(&mut prefix);
    prefix[0] = 0xfd;
    let hex = authkey::hex(&prefix);
    let insert = sqlx::query("INSERT INTO meta (key, value) VALUES (?1, ?2)")
        .bind(META_ULA_PREFIX)
        .bind(&hex)
        .execute(&mut **tx)
        .await;
    if insert.is_err() {
        // 并发初始化撞主键时复用先写入的值。
        if let Some(existing) = sqlx::query("SELECT value FROM meta WHERE key = ?1")
            .bind(META_ULA_PREFIX)
            .fetch_optional(&mut **tx)
            .await?
        {
            return parse_ula(&existing.get::<String, _>("value"));
        }
    }
    Ok(prefix)
}

fn parse_ula(hex_text: &str) -> anyhow::Result<[u8; 6]> {
    let bytes = hex_text.as_bytes();
    if bytes.len() != 12 || !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("meta 里的 ULA 前缀不是 12 位十六进制：{hex_text}");
    }
    let mut out = [0u8; 6];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex_text[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

fn parse_v4(text: &str) -> anyhow::Result<Ipv4Addr> {
    text.parse()
        .map_err(|e| anyhow::anyhow!("invalid ipv4 in db '{text}': {e}"))
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
