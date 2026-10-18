use std::path::PathBuf;

/// 平台默认状态目录（A4：Linux /var/lib/hzd，macOS /Library/Application Support/hzd）。
/// 纯函数，字面量可测；launchd 不继承 shell 环境变量，macOS 依赖此默认值。
pub fn default_state_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/hzd")
    } else {
        PathBuf::from("/var/lib/hzd")
    }
}

/// 状态目录：HZD_STATE_DIR 覆盖，否则按 A4 取平台默认。
pub fn state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("HZD_STATE_DIR") {
        return PathBuf::from(dir);
    }
    default_state_dir()
}

/// UDS 路径：HZD_SOCK_PATH 覆盖，默认 /var/run/hzd.sock。
pub fn socket_path() -> PathBuf {
    std::env::var_os("HZD_SOCK_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/run/hzd.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_default_state_dir_is_library_application_support() {
        assert_eq!(
            default_state_dir(),
            PathBuf::from("/Library/Application Support/hzd")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_default_state_dir_is_var_lib() {
        assert_eq!(default_state_dir(), PathBuf::from("/var/lib/hzd"));
    }
}
