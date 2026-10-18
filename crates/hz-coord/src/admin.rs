//! Admin 远程管理（FR-11 / #12）：签发/吊销 Auth Key、列出/改名/删除/吊销
//! Node。授权按 A3 建模为单一 [`Operator`]：每个请求先由调用方 Node 的
//! 归属解析出操作者，再按操作查唯一的权限表（下方每个辅助函数一个 match）。
//! Policy rpc 的 Admin 校验（#13）也复用这里的解析。

use tonic::Status;

use crate::store::{NodeRecord, NodeScope, RenameError, RevokeAuthKeyOutcome, Store};

/// 一次管理请求的操作者：调用方 Node 归属的 User（Admin 与否），
/// 或无归属的 Tagged（一律拒绝）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operator {
    Admin { user: String },
    User { user: String },
    Tagged,
}

/// Node 归属 → 操作者。归属 User 不在 users 表（被外部删行）按普通 User
/// 对待：能看自己名下，升不了 Admin，管理操作被 store 查询自然约束。
pub async fn resolve_operator(store: &Store, record: &NodeRecord) -> Result<Operator, Status> {
    let Some(owner) = record.owner_user.clone() else {
        return Ok(Operator::Tagged);
    };
    let is_admin = store
        .user_is_admin(&owner)
        .await
        .map_err(|e| {
            tracing::error!(%e, %owner, "lookup admin flag failed");
            Status::internal("查询 Admin 身份失败")
        })?
        .unwrap_or(false);
    Ok(if is_admin {
        Operator::Admin { user: owner }
    } else {
        Operator::User { user: owner }
    })
}

/// 仅 Admin 的操作（签发/吊销 Auth Key、吊销 Node）。
pub fn require_admin(operator: &Operator) -> Result<(), Status> {
    match operator {
        Operator::Admin { .. } => Ok(()),
        Operator::User { user } => Err(Status::permission_denied(format!(
            "需要 Admin 权限（当前操作者是普通 User {user}）"
        ))),
        Operator::Tagged => Err(Status::permission_denied("带 Tag 的 Node 不能执行管理操作")),
    }
}

/// Admin 任意 Node、普通 User 仅自己名下的操作（改名/删除）。
pub fn require_owner(operator: &Operator, target: &NodeRecord) -> Result<(), Status> {
    match operator {
        Operator::Admin { .. } => Ok(()),
        Operator::User { user } => {
            if target.owner_user.as_deref() == Some(user.as_str()) {
                Ok(())
            } else {
                Err(Status::permission_denied("只能操作自己名下的 Node"))
            }
        }
        Operator::Tagged => Err(Status::permission_denied("带 Tag 的 Node 不能执行管理操作")),
    }
}

/// 列表的可见范围：Admin 全部（含已吊销，供审计），普通 User 自己名下。
/// Tagged 无管理视图（查看也是管理操作的一部分，与 AC「任何管理操作被拒绝」一致）。
pub fn list_scope(operator: &Operator) -> Result<NodeScope, Status> {
    match operator {
        Operator::Admin { .. } => Ok(NodeScope::All),
        Operator::User { user } => Ok(NodeScope::OwnedBy(user.clone())),
        Operator::Tagged => Err(Status::permission_denied("带 Tag 的 Node 不能执行管理操作")),
    }
}

/// 目标 Node 必须在册（按 id 定位；不在册统一 NotFound，不区分已删/从未存在）。
pub async fn node_by_id(store: &Store, node_id: &str) -> Result<NodeRecord, Status> {
    store
        .node_row_by_id(node_id)
        .await
        .map_err(|e| {
            tracing::error!(%e, node_id, "load node for admin op failed");
            Status::internal("查询 Node 失败")
        })?
        .ok_or_else(|| Status::not_found(format!("Node {node_id} 不存在")))
}

/// 签发 Auth Key：过期时刻必填且须在未来。
pub async fn create_auth_key(
    store: &Store,
    expires_unix: i64,
    single_use: bool,
    tags: &[String],
) -> Result<(String, String), Status> {
    if expires_unix <= crate::store::unix_now() {
        return Err(Status::invalid_argument(
            "Auth Key 的过期时间必须晚于当前时刻",
        ));
    }
    store
        .create_auth_key_with_id(expires_unix, single_use, tags)
        .await
        .map_err(|e| {
            tracing::error!(%e, "create auth key failed");
            Status::internal("签发 Auth Key 失败")
        })
}

/// 吊销 Auth Key：在册但已死（过期/已吊销）是幂等成功，不在册 NotFound。
pub async fn revoke_auth_key(store: &Store, key_id: &str) -> Result<(), Status> {
    match store.revoke_auth_key(key_id).await.map_err(|e| {
        tracing::error!(%e, key_id, "revoke auth key failed");
        Status::internal("吊销 Auth Key 失败")
    })? {
        RevokeAuthKeyOutcome::Revoked | RevokeAuthKeyOutcome::AlreadyDead => Ok(()),
        RevokeAuthKeyOutcome::Missing => {
            Err(Status::not_found(format!("Auth Key {key_id} 不存在")))
        }
    }
}

/// 改名：规范化 → 权限 → 唯一性。冲突 AlreadyExists，整份拒绝（无 -2 兜底）。
pub async fn rename_node(
    store: &Store,
    operator: &Operator,
    node_id: &str,
    raw_name: &str,
) -> Result<String, Status> {
    let target = node_by_id(store, node_id).await?;
    require_owner(operator, &target)?;
    let normalized = crate::name::NodeName::normalize(raw_name);
    match store.rename_node(node_id, &normalized).await {
        Ok(record) => {
            tracing::info!(node_id, from = %target.name, to = %record.name, "node renamed");
            Ok(record.name)
        }
        Err(RenameError::NameTaken(name)) => {
            Err(Status::already_exists(format!("Node Name 已存在：{name}")))
        }
        Err(RenameError::Missing) => Err(Status::not_found(format!("Node {node_id} 不存在"))),
        Err(RenameError::Store(e)) => {
            tracing::error!(%e, node_id, "rename node failed");
            Err(Status::internal("改名失败"))
        }
    }
}

/// 删除：硬删行。存储变更信号让 fan-out 把 removed 差量推给全部订阅者。
pub async fn delete_node(store: &Store, operator: &Operator, node_id: &str) -> Result<(), Status> {
    let target = node_by_id(store, node_id).await?;
    require_owner(operator, &target)?;
    store
        .delete_node(node_id)
        .await
        .map_err(|e| {
            tracing::error!(%e, node_id, "delete node failed");
            Status::internal("删除 Node 失败")
        })?
        .then_some(())
        .ok_or_else(|| Status::not_found(format!("Node {node_id} 不存在")))
}

/// 吊销 Node（仅 Admin）：保留行供审计；notify 让全部 Map 立即移除，
/// 下一次任何认额（Map 订阅、RelayCheck、注册刷新）都会被拒。
pub async fn revoke_node(store: &Store, node_id: &str) -> Result<(), Status> {
    let target = node_by_id(store, node_id).await?;
    store.revoke_node(node_id).await.map_err(|e| {
        tracing::error!(%e, node_id, "revoke node failed");
        Status::internal("吊销 Node 失败")
    })?;
    tracing::info!(node_id, name = %target.name, "node revoked by admin");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_with(owner: Option<&str>) -> NodeRecord {
        NodeRecord {
            id: "n1".to_string(),
            name: "node-1".to_string(),
            ipv4: "100.96.0.1".parse().unwrap(),
            ipv6: "fd00::1".parse().unwrap(),
            tags: vec![],
            owner_user: owner.map(str::to_string),
            expires_at_unix: None,
            node_key_pub: vec![1u8; 32],
            udp_endpoints: Vec::new(),
        }
    }

    #[test]
    fn permission_table_matches_spec() {
        let admin = Operator::Admin {
            user: "alice".into(),
        };
        let user = Operator::User { user: "bob".into() };
        let tagged = Operator::Tagged;
        let bob_node = record_with(Some("bob"));
        let alien_node = record_with(Some("carol"));

        require_admin(&admin).unwrap();
        for op in [&user, &tagged] {
            let status = require_admin(op).unwrap_err();
            assert_eq!(status.code(), tonic::Code::PermissionDenied);
        }
        assert!(
            require_admin(&user)
                .unwrap_err()
                .message()
                .contains("需要 Admin 权限")
        );
        assert!(
            require_admin(&tagged)
                .unwrap_err()
                .message()
                .contains("带 Tag")
        );

        require_owner(&admin, &alien_node).unwrap();
        require_owner(&user, &bob_node).unwrap();
        let status = require_owner(&user, &alien_node).unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(
            status.message().contains("只能操作自己名下的 Node"),
            "{}",
            status
        );
        require_owner(&tagged, &bob_node).unwrap_err();

        assert!(matches!(list_scope(&admin).unwrap(), NodeScope::All));
        match list_scope(&user).unwrap() {
            NodeScope::OwnedBy(owner) => assert_eq!(owner, "bob"),
            other => panic!("普通 User 的范围应是 OwnedBy：{other:?}"),
        }
        list_scope(&tagged).unwrap_err();
    }
}
