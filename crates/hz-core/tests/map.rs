//! NetworkMapCache 的 reducer 与持久化契约：全量/增量归并出正确的快照与变化，
//! 进程状态丢弃后从 network-map.json 恢复出同一份快照。

use std::path::Path;

use hz_core::map::{MapChange, MapNode, NetworkMapCache};

fn node(id: &str, name: &str, endpoints: &[&str]) -> MapNode {
    MapNode {
        node_id: id.to_string(),
        name: name.to_string(),
        ipv4: format!("100.96.0.{id}"),
        ipv6: format!("fd00::96:0:0:{id}"),
        tags: vec![],
        owner_user: None,
        expires_at_unix: None,
        node_key_pub: vec![0u8; 32],
        endpoints: endpoints.iter().map(|e| e.to_string()).collect(),
        detailed_endpoints: vec![],
    }
}

#[test]
fn full_apply_replaces_set_and_reports_the_diff() {
    let dir = tempfile::tempdir().unwrap();
    let cache = NetworkMapCache::load(dir.path()).unwrap();

    let change = cache.apply_full(vec![node("1", "alpha", &["10.0.0.1:51820"])]);
    assert_eq!(
        change,
        MapChange {
            added_or_updated: vec![node("1", "alpha", &["10.0.0.1:51820"])],
            removed_node_ids: vec![],
        }
    );
    assert_eq!(cache.version(), 1);

    let change = cache.apply_full(vec![node("1", "alpha", &["10.0.0.1:51820"])]);
    assert!(change.is_empty(), "同一份快照重放必须是无变化：{change:?}");
    assert_eq!(cache.version(), 1, "无变化不推版本号");

    let change = cache.apply_full(vec![
        node("1", "alpha", &["10.0.0.9:51820"]),
        node("2", "beta", &[]),
    ]);
    assert_eq!(
        change,
        MapChange {
            added_or_updated: vec![
                node("1", "alpha", &["10.0.0.9:51820"]),
                node("2", "beta", &[])
            ],
            removed_node_ids: vec![],
        }
    );

    let change = cache.apply_full(vec![node("2", "beta", &[])]);
    assert_eq!(change.removed_node_ids, vec!["1".to_string()]);
    assert_eq!(cache.snapshot(), vec![node("2", "beta", &[])]);
}

#[test]
fn delta_apply_merges_updates_and_removals() {
    let dir = tempfile::tempdir().unwrap();
    let cache = NetworkMapCache::load(dir.path()).unwrap();
    cache.apply_full(vec![node("1", "alpha", &[]), node("2", "beta", &[])]);

    let change = cache.apply_delta(
        vec![
            node("2", "beta", &["192.168.7.2:51820"]),
            node("3", "gamma", &[]),
        ],
        vec!["1".to_string(), "404".to_string()],
    );
    assert_eq!(change.added_or_updated.len(), 2);
    assert_eq!(
        change.removed_node_ids,
        vec!["1".to_string()],
        "未知 id 的移除是空操作"
    );

    assert_eq!(
        cache.snapshot(),
        vec![
            node("2", "beta", &["192.168.7.2:51820"]),
            node("3", "gamma", &[]),
        ]
    );
}

#[test]
fn cache_survives_process_restart_via_disk_file() {
    let state_dir = tempfile::tempdir().unwrap();
    let expected = {
        let cache = NetworkMapCache::load(state_dir.path()).unwrap();
        cache.apply_full(vec![node("1", "alpha", &["10.0.0.1:51820"])]);
        cache.apply_delta(
            vec![node("2", "beta", &["192.168.7.2:51820"])],
            vec!["1".to_string()],
        );
        cache.snapshot()
    };

    let reloaded = NetworkMapCache::load(state_dir.path()).unwrap();
    assert_eq!(
        reloaded.snapshot(),
        expected,
        "重启后快照必须等于落盘前的集合"
    );

    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(state_dir.path().join("network-map.json"))
            .unwrap()
            .permissions()
            .mode()
    };
    assert_eq!(mode & 0o777, 0o600, "缓存文件权限必须是 0600");
}

#[test]
fn missing_cache_file_starts_empty() {
    let dir = tempfile::tempdir().unwrap();
    let cache = NetworkMapCache::load(Path::new(dir.path())).unwrap();
    assert!(cache.snapshot().is_empty());
    assert_eq!(cache.version(), 0);
}
