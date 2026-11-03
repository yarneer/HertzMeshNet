//! 桌面系统 DNS 接入（FR-5 / A2 的平台部分）：systemd-resolved 环境写
//! conf.d/hznet.conf 分域接管（`Domains=~<suffix>`，只吃 HzNet 后缀）；
//! 无 systemd 的容器/测试环境在 HZD_DNS_RESOLVCONF_FALLBACK=1 显式要求下才
//! 重写 /etc/resolv.conf，停止时逐字节还原；macOS 写 `/etc/resolver/<suffix>`
//! 分域接管（mDNSResponder 按文件名匹配后缀，只吃 HzNet 后缀），停止时删除
//! 或逐字节还原；三者之外的文件一概不碰。
//! 段内应答器（`*.hznet.internal` 的 A/AAAA 应答）是平台无关部分，在
//! hz-engine；本模块只管"把系统的后缀查询指到应答器"。
//! 接入时机：桌面 Platform::establish（数据面每次拉起，含 up 恢复）；还原
//! 时机：数据面 down（引擎钩子）与进程退出（信号 / Drop 双路径）。

#[allow(unused_imports)]
pub use hz_engine::dns::spawn_responder;

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;

/// systemd-resolved 分域接管的声明式配置；render 是纯函数，字面量可测。
pub struct ResolvedConfig {
    pub suffix: String,
    pub dns_addr: Ipv4Addr,
}

impl ResolvedConfig {
    pub fn render(&self) -> String {
        format!(
            "[Resolve]\nDNS={}\nDomains=~{}\n",
            self.dns_addr, self.suffix
        )
    }
}

/// macOS `/etc/resolver/<suffix>` 分域接管的声明式配置；文件名即接管的后缀，
/// mDNSRecognizer 只把该后缀的查询交给指定 nameserver。render 是纯函数，
/// 字面量可测。
pub struct ResolverFileConfig {
    pub suffix: String,
    pub dns_addr: Ipv4Addr,
}

impl ResolverFileConfig {
    pub fn render(&self) -> String {
        format!("nameserver {}\n", self.dns_addr)
    }
}

/// resolv.conf 显式退路的生成内容：本服务 nameserver 置顶（后缀内应答、
/// 后缀外 REFUSED 让 glibc 顺序落到原 nameserver），search 合并进后缀。
/// 纯函数，字面量可测。
pub fn fallback_resolvconf_content(previous: &str, dns: Ipv4Addr, suffix: &str) -> String {
    let mut out = format!("nameserver {dns}\n");
    let mut search = vec![suffix.to_string()];
    for line in previous.lines() {
        let mut parts = line.split_whitespace();
        match parts.next().unwrap_or_default() {
            keyword
                if keyword.eq_ignore_ascii_case("search")
                    || keyword.eq_ignore_ascii_case("domain") =>
            {
                search.extend(parts.map(str::to_string));
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out.push_str(&format!("search {}\n", search.join(" ")));
    out
}

/// 系统接入点；测试用临时目录注入。
pub struct SystemDnsPaths {
    pub resolved_conf: PathBuf,
    pub resolv_conf: PathBuf,
    /// macOS `/etc/resolver/<suffix>`；Linux 机制不会选它。
    pub resolver_file: PathBuf,
}

impl SystemDnsPaths {
    pub fn system() -> Self {
        let suffix = hz_core::dns::dns_suffix();
        Self {
            // systemd-resolved 的 drop-in 目录是 resolved.conf.d（中缀 .conf），
            // 写到 resolved/conf.d 不会被子加载，分域静默失效。
            resolved_conf: PathBuf::from("/etc/systemd/resolved.conf.d/hznet.conf"),
            resolv_conf: PathBuf::from("/etc/resolv.conf"),
            resolver_file: PathBuf::from("/etc/resolver").join(suffix),
        }
    }
}

/// 本平台的系统接入机制（FR-5）：macOS 走 /etc/resolver/ 分域接管，
/// 其余走 systemd-resolved（退路见 allow_fallback）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mechanism {
    ResolvedOrFallback,
    ResolverFile,
}

impl Mechanism {
    fn system() -> Self {
        if cfg!(target_os = "macos") {
            Mechanism::ResolverFile
        } else {
            Mechanism::ResolvedOrFallback
        }
    }
}

enum Integration {
    /// conf.d/hznet.conf：启动前不存在则停止时删除，存在则原样还原。
    ResolvedConf {
        path: PathBuf,
        previous: Option<Vec<u8>>,
    },
    /// HZD_DNS_RESOLVCONF_FALLBACK=1 的容器退路：停止时逐字节还原。
    ResolvConfFallback {
        path: PathBuf,
        previous: Vec<u8>,
    },
    /// macOS `/etc/resolver/<suffix>`：快照/还原语义与 ResolvedConf 相同
    /// （启动前不存在则停止时删除，存在则原样还原）。
    ResolverFile {
        path: PathBuf,
        previous: Option<Vec<u8>>,
    },
    None,
}

impl Integration {
    fn apply(
        paths: &SystemDnsPaths,
        config: &ResolvedConfig,
        mechanism: Mechanism,
        allow_fallback: bool,
    ) -> Integration {
        if mechanism == Mechanism::ResolverFile {
            let resolver_config = ResolverFileConfig {
                suffix: config.suffix.clone(),
                dns_addr: config.dns_addr,
            };
            return apply_resolver_file(&paths.resolver_file, &resolver_config);
        }
        let Some(conf_dir) = paths.resolved_conf.parent().map(PathBuf::from) else {
            return Integration::None;
        };
        if conf_dir.exists() {
            let previous = std::fs::read(&paths.resolved_conf).ok();
            let write = std::fs::create_dir_all(&conf_dir)
                .and_then(|()| std::fs::write(&paths.resolved_conf, config.render()));
            match write {
                Ok(()) => {
                    tracing::info!(
                        path = %paths.resolved_conf.display(),
                        "systemd-resolved domain-split config written"
                    );
                    flush_resolved_caches();
                    return Integration::ResolvedConf {
                        path: paths.resolved_conf.clone(),
                        previous,
                    };
                }
                Err(error) => {
                    tracing::warn!(%error, "write systemd-resolved config failed");
                }
            }
        }
        if allow_fallback {
            match std::fs::read_to_string(&paths.resolv_conf) {
                Ok(previous) => {
                    let content =
                        fallback_resolvconf_content(&previous, config.dns_addr, &config.suffix);
                    match std::fs::write(&paths.resolv_conf, &content) {
                        Ok(()) => {
                            tracing::info!(
                                path = %paths.resolv_conf.display(),
                                "resolv.conf fallback written (explicit env)"
                            );
                            return Integration::ResolvConfFallback {
                                path: paths.resolv_conf.clone(),
                                previous: previous.into_bytes(),
                            };
                        }
                        Err(error) => {
                            tracing::warn!(%error, "write resolv.conf fallback failed");
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "read resolv.conf failed, skip fallback");
                }
            }
        }
        Integration::None
    }

    fn restore(self) -> anyhow::Result<()> {
        match self {
            Integration::ResolvedConf { path, previous } => {
                restore_written_file(&path, previous)?;
                flush_resolved_caches();
            }
            Integration::ResolverFile { path, previous } => {
                restore_written_file(&path, previous)?;
            }
            Integration::ResolvConfFallback { path, previous } => {
                std::fs::write(&path, previous)?;
            }
            Integration::None => {}
        }
        Ok(())
    }
}

fn flush_resolved_caches() {
    match std::process::Command::new("resolvectl")
        .args(["flush-caches"])
        .output()
    {
        Ok(output) if output.status.success() => {}
        _ => tracing::debug!("resolvectl flush-caches unavailable, skipped"),
    }
}

/// 启动前不存在则停止时删除，存在则逐字节还原（ResolvedConf 与
/// ResolverFile 共用的快照/还原语义）。
fn restore_written_file(path: &std::path::Path, previous: Option<Vec<u8>>) -> anyhow::Result<()> {
    match previous {
        Some(bytes) => std::fs::write(path, bytes)?,
        None => match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        },
    }
    Ok(())
}

/// macOS：写 `/etc/resolver/<suffix>`（目录不存在则创建，须 root；
/// 测试用临时目录注入）。写失败降级为 None（应答器仍在，仅系统接入缺失）。
fn apply_resolver_file(path: &std::path::Path, config: &ResolverFileConfig) -> Integration {
    let previous = std::fs::read(path).ok();
    let write = std::fs::create_dir_all(path.parent().unwrap_or_else(|| std::path::Path::new("/")))
        .and_then(|()| std::fs::write(path, config.render()));
    match write {
        Ok(()) => {
            tracing::info!(path = %path.display(), "resolver file written (domain split)");
            Integration::ResolverFile {
                path: path.to_path_buf(),
                previous,
            }
        }
        Err(error) => {
            tracing::warn!(%error, "write resolver file failed");
            Integration::None
        }
    }
}

/// 信号/Drop 双路径的还原闸门；restore 幂等。
struct ShutdownGuard(StdMutex<Option<Integration>>);

impl ShutdownGuard {
    fn restore(&self) {
        if let Some(integration) = self.0.lock().expect("dns guard poisoned").take() {
            if let Err(error) = integration.restore() {
                tracing::warn!(%error, "restore system dns config failed");
            }
        }
    }

    /// up 恢复（#81）：换入新的接入快照（apply 已把文件写好，旧的不需要还原）。
    fn replace(&self, integration: Integration) {
        self.0
            .lock()
            .expect("dns guard poisoned")
            .replace(integration);
    }
}

/// 进程级接入快照槽：down 主动还原 / up 重新接入共用（#81）。
static GUARD: std::sync::OnceLock<Arc<ShutdownGuard>> = std::sync::OnceLock::new();

/// down（#81）：还原系统 DNS 接入（/etc/resolver 条目或 resolv.conf 快照），
/// 幂等；应答器与辅助地址不动（接口随数据面拆除消失）。
pub fn deactivate() {
    if let Some(guard) = GUARD.get() {
        guard.restore();
    }
}
/// 数据面拉起（含 up 恢复）时的系统接入：写 resolver 配置并登记还原快照。
/// 辅助地址由 establish 先挂好；应答器在 hz-engine 随数据面幂等启动。
pub fn integrate(dns_v4: Ipv4Addr, allow_fallback: bool) {
    let integration = Integration::apply(
        &SystemDnsPaths::system(),
        &ResolvedConfig {
            suffix: hz_core::dns::dns_suffix(),
            dns_addr: dns_v4,
        },
        Mechanism::system(),
        allow_fallback,
    );
    let guard = GUARD.get_or_init(|| {
        let guard = Arc::new(ShutdownGuard(StdMutex::new(None)));
        spawn_signal_task(guard.clone());
        guard
    });
    guard.replace(integration);
}

/// SIGTERM/SIGINT 先还原系统配置再以默认处置退出；正常退出路径由 Drop 兜底。
#[cfg(unix)]
fn spawn_signal_task(guard: Arc<ShutdownGuard>) {
    tokio::spawn(async move {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => return,
            };
        let mut interrupt =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
                Ok(signal) => signal,
                Err(_) => return,
            };
        let signal_number = tokio::select! {
            _ = terminate.recv() => libc::SIGTERM,
            _ = interrupt.recv() => libc::SIGINT,
        };
        guard.restore();
        tracing::info!(signal = signal_number, "dns config restored, terminating");
        unsafe {
            libc::signal(signal_number, libc::SIG_DFL);
            libc::raise(signal_number);
        }
        std::process::exit(128 + signal_number);
    });
}

#[cfg(not(unix))]
fn spawn_signal_task(_guard: Arc<ShutdownGuard>) {}

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;
    use hz_core::dns::DNS_BIND_V4;

    #[test]
    fn resolved_config_renders_literal_content() {
        let config = ResolvedConfig {
            suffix: "corp.mesh".to_string(),
            dns_addr: Ipv4Addr::new(100, 96, 0, 53),
        };
        assert_eq!(
            config.render(),
            "[Resolve]\nDNS=100.96.0.53\nDomains=~corp.mesh\n"
        );
    }

    #[test]
    fn fallback_resolvconf_content_merges_search_and_keeps_other_lines() {
        let previous = "nameserver 127.0.0.11\nsearch corp.docker\noptions ndots:0\n";
        assert_eq!(
            fallback_resolvconf_content(previous, Ipv4Addr::new(100, 96, 0, 53), "hznet.internal"),
            "nameserver 100.96.0.53\nnameserver 127.0.0.11\noptions ndots:0\nsearch hznet.internal corp.docker\n"
        );
    }

    #[test]
    fn integration_writes_then_removes_hznet_conf_without_touching_neighbors() {
        let dir = tempfile::tempdir().unwrap();
        let conf_dir = dir.path().join("conf.d");
        std::fs::create_dir_all(&conf_dir).unwrap();
        std::fs::write(conf_dir.join("other.conf"), "keep me\n").unwrap();
        let paths = SystemDnsPaths {
            resolved_conf: conf_dir.join("hznet.conf"),
            resolv_conf: dir.path().join("resolv.conf"),
            resolver_file: dir.path().join("resolver").join("hznet.internal"),
        };
        let config = ResolvedConfig {
            suffix: "hznet.internal".to_string(),
            dns_addr: DNS_BIND_V4,
        };

        let integration = Integration::apply(&paths, &config, Mechanism::ResolvedOrFallback, false);
        assert_eq!(
            std::fs::read_to_string(&paths.resolved_conf).unwrap(),
            config.render()
        );
        integration.restore().unwrap();

        assert!(!paths.resolved_conf.exists(), "停止后 hznet.conf 应被删除");
        assert_eq!(
            std::fs::read_to_string(conf_dir.join("other.conf")).unwrap(),
            "keep me\n",
            "无关的 resolved 配置不得被动"
        );
    }

    #[test]
    fn integration_restores_preexisting_hznet_conf_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let conf_dir = dir.path().join("conf.d");
        std::fs::create_dir_all(&conf_dir).unwrap();
        std::fs::write(conf_dir.join("hznet.conf"), "[Resolve]\nDNS=10.0.0.1\n").unwrap();
        let paths = SystemDnsPaths {
            resolved_conf: conf_dir.join("hznet.conf"),
            resolv_conf: dir.path().join("resolv.conf"),
            resolver_file: dir.path().join("resolver").join("hznet.internal"),
        };
        let config = ResolvedConfig {
            suffix: "hznet.internal".to_string(),
            dns_addr: DNS_BIND_V4,
        };

        Integration::apply(&paths, &config, Mechanism::ResolvedOrFallback, false)
            .restore()
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&paths.resolved_conf).unwrap(),
            "[Resolve]\nDNS=10.0.0.1\n",
            "启动前就存在的 hznet.conf 停止时逐字节还原"
        );
    }

    #[test]
    fn fallback_integration_rewrites_and_restores_resolv_conf_only_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        let original = "nameserver 127.0.0.11\noptions ndots:0\n";
        std::fs::write(dir.path().join("resolv.conf"), original).unwrap();
        let paths = SystemDnsPaths {
            resolved_conf: dir.path().join("conf.d").join("hznet.conf"),
            resolv_conf: dir.path().join("resolv.conf"),
            resolver_file: dir.path().join("resolver").join("hznet.internal"),
        };
        let config = ResolvedConfig {
            suffix: "hznet.internal".to_string(),
            dns_addr: DNS_BIND_V4,
        };

        assert!(matches!(
            Integration::apply(&paths, &config, Mechanism::ResolvedOrFallback, false),
            Integration::None
        ));
        assert_eq!(
            std::fs::read_to_string(&paths.resolv_conf).unwrap(),
            original,
            "未显式要求退路时绝不改 resolv.conf"
        );

        Integration::apply(&paths, &config, Mechanism::ResolvedOrFallback, true)
            .restore()
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&paths.resolv_conf).unwrap(),
            original,
            "停止后 resolv.conf 逐字节还原"
        );
    }

    #[test]
    fn resolver_file_mechanism_writes_only_the_resolver_file() {
        let dir = tempfile::tempdir().unwrap();
        let conf_dir = dir.path().join("conf.d");
        std::fs::create_dir_all(&conf_dir).unwrap();
        let paths = SystemDnsPaths {
            resolved_conf: conf_dir.join("hznet.conf"),
            resolv_conf: dir.path().join("resolv.conf"),
            resolver_file: dir.path().join("resolver").join("hznet.internal"),
        };
        let config = ResolvedConfig {
            suffix: "hznet.internal".to_string(),
            dns_addr: DNS_BIND_V4,
        };

        let integration = Integration::apply(&paths, &config, Mechanism::ResolverFile, false);
        assert_eq!(
            std::fs::read_to_string(&paths.resolver_file).unwrap(),
            "nameserver 100.96.0.53\n",
            "resolver-file 机制应写 /etc/resolver/<suffix> 形态"
        );
        assert!(
            !paths.resolved_conf.exists(),
            "macOS 机制绝不写 systemd-resolved 配置"
        );
        assert!(!paths.resolv_conf.exists(), "macOS 机制绝不改 resolv.conf");
        integration.restore().unwrap();
        assert!(!paths.resolver_file.exists(), "停止后应删除 resolver 文件");
    }

    #[test]
    fn resolver_file_renders_nameserver_only() {
        let config = ResolverFileConfig {
            suffix: "hznet.internal".to_string(),
            dns_addr: Ipv4Addr::new(100, 96, 0, 53),
        };
        assert_eq!(config.render(), "nameserver 100.96.0.53\n");
    }

    #[test]
    fn resolver_file_integration_creates_dir_writes_then_removes_on_stop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolver").join("hznet.internal");
        let config = ResolverFileConfig {
            suffix: "hznet.internal".to_string(),
            dns_addr: DNS_BIND_V4,
        };

        let integration = apply_resolver_file(&path, &config);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "nameserver 100.96.0.53\n"
        );
        integration.restore().unwrap();
        assert!(!path.exists(), "停止后 /etc/resolver/<suffix> 应被删除");
        assert!(path.parent().unwrap().exists(), "resolver 目录本身保留");
    }

    #[test]
    fn resolver_file_integration_restores_preexisting_file_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let resolver_dir = dir.path().join("resolver");
        std::fs::create_dir_all(&resolver_dir).unwrap();
        let path = resolver_dir.join("corp.mesh");
        std::fs::write(&path, "nameserver 10.0.0.1\n").unwrap();
        let config = ResolverFileConfig {
            suffix: "corp.mesh".to_string(),
            dns_addr: DNS_BIND_V4,
        };

        apply_resolver_file(&path, &config).restore().unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "nameserver 10.0.0.1\n",
            "启动前就存在的 resolver 文件停止时逐字节还原"
        );
    }
}
