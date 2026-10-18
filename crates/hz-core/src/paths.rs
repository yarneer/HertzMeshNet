use std::path::PathBuf;

/// 状态目录：HZD_STATE_DIR 覆盖，否则按 A4 取平台默认（Linux /var/lib/hzd，macOS /Library/Application Support/hzd）。
pub fn state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("HZD_STATE_DIR") {
        return PathBuf::from(dir);
    }
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/hzd")
    } else {
        PathBuf::from("/var/lib/hzd")
    }
}

/// UDS 路径：HZD_SOCK_PATH 覆盖，默认 /var/run/hzd.sock。
pub fn socket_path() -> PathBuf {
    std::env::var_os("HZD_SOCK_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/run/hzd.sock"))
}
