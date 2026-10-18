use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use hz_core::keys::KeyStore;

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn keys_survive_reload_with_exact_file_modes() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();

    let keys = KeyStore::load_or_create(state).unwrap();
    let machine_public = keys.machine_public();
    let node_public = keys.node_public();
    drop(keys);

    let reloaded = KeyStore::load_or_create(state).unwrap();
    assert_eq!(
        reloaded.machine_public(),
        machine_public,
        "Machine Key 必须跨重启不变"
    );
    assert_eq!(
        reloaded.node_public(),
        node_public,
        "Node Key 必须跨重启不变"
    );
    drop(reloaded);

    let again = KeyStore::load_or_create(state).unwrap();
    assert_eq!(
        again.machine_public(),
        machine_public,
        "重复加载必须复用已有密钥文件"
    );

    assert_eq!(mode_of(&state.join("machine-key")), 0o600);
    assert_eq!(mode_of(&state.join("node-key")), 0o600);
    assert_eq!(mode_of(&state.join("machine-key.pub")), 0o644);
    assert_eq!(mode_of(&state.join("node-key.pub")), 0o644);
}

#[test]
fn corrupt_machine_key_file_is_an_error_not_a_silent_rotation() {
    let dir = tempfile::tempdir().unwrap();
    KeyStore::load_or_create(dir.path()).unwrap();
    std::fs::write(dir.path().join("machine-key"), "!!!not-base64!!!").unwrap();

    let result = KeyStore::load_or_create(dir.path());
    assert!(
        result.is_err(),
        "损坏的密钥文件必须报错，静默重新生成等于轮换 Node 身份"
    );
}

#[test]
fn staged_node_rotation_only_lands_on_commit() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let keys = KeyStore::load_or_create(state).unwrap();
    let before = keys.node_public();
    let machine_before = keys.machine_public();

    let (secret, staged_public) = keys.stage_node_rotation();
    assert_ne!(staged_public, before, "轮换必须产生新公钥");
    assert_eq!(
        keys.node_public(),
        before,
        "stage 不落盘不生效，登录失败时数据面继续用旧密钥"
    );

    let committed = keys.commit_node_rotation(state, &secret).unwrap();
    assert_eq!(committed, staged_public);
    assert_eq!(keys.node_public(), staged_public);
    assert_eq!(
        keys.machine_public(),
        machine_before,
        "轮换 Node Key 绝不动 Machine Key（ADR-0005）"
    );

    let reloaded = KeyStore::load_or_create(state).unwrap();
    assert_eq!(
        reloaded.node_public(),
        staged_public,
        "轮换必须持久化，重启后仍是新密钥"
    );
    assert_eq!(
        std::fs::read_to_string(state.join("node-key.pub"))
            .unwrap()
            .trim(),
        B64.encode(staged_public),
        "node-key.pub 是推导物，轮换时必须同步覆盖"
    );
    assert_eq!(mode_of(&state.join("node-key")), 0o600);
}
