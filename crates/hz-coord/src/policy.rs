//! Policy 的服务端规则（FR-10）：结构校验之后的引用存在性校验（依赖
//! users 表），以及管理操作的身份授权（A3）。授权助手按可复用形态写，
//! #12 把其余管理 rpc 接上时直接调用。

use hz_core::policy::{PolicyDoc, parse_policy, referenced_users};
use tonic::Status;

use crate::store::{NodeRecord, Store};

/// 完整校验：结构（hz-core 纯函数）+ user: 引用与 Group 成员必须在
/// users 表里存在。任何一条不过，整份拒绝（现行 Policy 不变）。
pub async fn validate_policy(store: &Store, content: &str) -> Result<PolicyDoc, Status> {
    let doc = parse_policy(content).map_err(|reason| {
        tracing::warn!(%reason, "policy rejected: structural validation failed");
        Status::invalid_argument(format!("Policy 校验失败：{reason}"))
    })?;
    let known = store
        .user_names()
        .await
        .map_err(|e| Status::internal(format!("查询 users 失败：{e}")))?;
    for name in referenced_users(&doc) {
        if !known.contains(&name) {
            let reason = format!("引用的 User {name:?} 不存在");
            tracing::warn!(%reason, "policy rejected");
            return Err(Status::invalid_argument(format!(
                "Policy 校验失败：{reason}"
            )));
        }
    }
    Ok(doc)
}

/// 管理操作授权（A3）：调用 rpc 的 Node 必须归属一个 Admin User。
/// 带 Tag 的 Node 无归属，直接拒绝；#12 的其余管理 rpc 复用本函数。
pub async fn authorize_admin(store: &Store, record: &NodeRecord) -> Result<(), Status> {
    let Some(owner) = record.owner_user.as_deref() else {
        return Err(Status::permission_denied(
            "带 Tag 的 Node 不归属任何 User，不能执行管理操作",
        ));
    };
    match store.user_is_admin(owner).await {
        Ok(Some(true)) => Ok(()),
        Ok(_) => Err(Status::permission_denied(format!(
            "User {owner} 不是 Admin，无法执行此管理操作"
        ))),
        Err(e) => {
            tracing::error!(%e, %owner, "lookup admin flag failed");
            Err(Status::internal("查询 Admin 身份失败"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

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

    #[tokio::test]
    async fn authorize_admin_rejects_tagged_and_non_admin_owners() {
        let store = Store::open_in_memory(crate::addr::AddressConfig::default())
            .await
            .unwrap();

        let tagged = record_with(None);
        let status = authorize_admin(&store, &tagged).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(status.message().contains("带 Tag"), "{status}");

        let admin_id = store.upsert_user("alice", true).await.unwrap();
        let plain_id = store.upsert_user("bob", false).await.unwrap();
        let bob = record_with(store_owner(&store, &plain_id).await.as_deref());
        let status = authorize_admin(&store, &bob).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(status.message().contains("不是 Admin"), "{status}");

        let alice = record_with(store_owner(&store, &admin_id).await.as_deref());
        authorize_admin(&store, &alice)
            .await
            .expect("Admin 归属的 Node 应通过授权");
    }

    /// 从 users 表取回名字（模拟 NodeRecord 的 owner_user 装载路径）。
    async fn store_owner(store: &Store, user_id: &str) -> Option<String> {
        sqlx::query("SELECT name FROM users WHERE id = ?1")
            .bind(user_id)
            .fetch_optional(store.pool())
            .await
            .unwrap()
            .map(|row| row.get::<String, _>("name"))
    }

    #[tokio::test]
    async fn validate_policy_rejects_unknown_user_refs() {
        let store = Store::open_in_memory(crate::addr::AddressConfig::default())
            .await
            .unwrap();
        store.upsert_user("alice", true).await.unwrap();

        let content = "[[rule]]\nfrom = \"user:ghost\"\nto = \"tag:db\"\nports = [80]\n";
        let status = validate_policy(&store, content).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("ghost"), "{status}");

        let content = "[[group]]\nname = \"dev\"\nusers = [\"alice\", \"ghost\"]\n";
        let status = validate_policy(&store, content).await.unwrap_err();
        assert!(
            status.message().contains("ghost"),
            "Group 成员同样要查：{status}"
        );

        let content = "[[group]]\nname = \"dev\"\nusers = [\"alice\"]\n[[rule]]\nfrom = \"group:dev\"\nto = \"tag:db\"\nports = [5432]\n";
        validate_policy(&store, content)
            .await
            .expect("全部引用可解析的 Policy 应通过");
    }
}
