//! `hz-coord` 子命令：serve（常驻 gRPC 服务）与 bootstrap（签发第一把 Auth Key）。

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tonic::transport::{Identity, ServerTlsConfig};

use crate::http::DistConfig;
use crate::oidc::OidcConfig;
use crate::service::{ServeConfig, serve};
use crate::store::{RangeFlags, Store};

#[derive(Parser)]
#[command(name = "hz-coord", version, about = "HzNet Coordination Server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// serve 的 flag 数量随部署面（TLS/OIDC/metrics/分发）自然增长，两个子命令的
// 尺寸差是 clap 参数枚举的常态，不值得为此 Box。
#[allow(clippy::large_enum_variant)]
enum Command {
    /// 启动 Coordination Server
    Serve {
        /// SQLite 数据库路径
        #[arg(long)]
        db: PathBuf,
        /// IPv4 地址段（FR-4）：首次初始化固化到库；与库中固化值不同且已有 Node 时拒绝。
        #[arg(long)]
        cidr: Option<String>,
        /// 额外保留地址（可重复出现），从不分配给 Node。
        #[arg(long = "reserve")]
        reserve: Vec<std::net::Ipv4Addr>,
        /// 监听地址，如 0.0.0.0:443
        #[arg(long)]
        listen: String,
        /// TLS 证书 PEM（与 --tls-key 成对出现）
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// TLS 私钥 PEM
        #[arg(long)]
        tls_key: Option<PathBuf>,
        /// 交互式登录 HTTP 面监听地址（如 0.0.0.0:8443；回调所在）
        #[arg(long)]
        http_listen: Option<String>,
        /// OIDC issuer，如 https://auth.example.com
        #[arg(long, requires = "http_listen")]
        oidc_issuer: Option<String>,
        /// OIDC client_id
        #[arg(long, requires = "oidc_issuer")]
        oidc_client_id: Option<String>,
        /// OIDC client secret
        #[arg(long, requires = "oidc_issuer")]
        oidc_client_secret: Option<String>,
        /// 注册到 IdP 的回调地址；缺省按 http_listen 的端口拼 http://127.0.0.1:<port>/oidc/callback
        #[arg(long)]
        oidc_redirect_uri: Option<String>,
        /// IdP 自签 CA 证书 PEM 路径（可选）
        #[arg(long)]
        oidc_ca: Option<PathBuf>,
        /// 交互式登录授予的 Node 有效期天数（默认 90）
        #[arg(long, default_value_t = 90)]
        login_node_ttl_days: i64,
        /// Prometheus /metrics 监听地址（默认 127.0.0.1:9100；off 关闭）
        #[arg(long)]
        metrics_listen: Option<String>,
        /// 分发目录（FR-13）：内含 <os>-<arch>/{hzd,hz}，经 --http-listen 下发 /install.sh 与 /dl/
        #[arg(long, requires = "http_listen")]
        dist_dir: Option<PathBuf>,
        /// 浏览器与安装脚本可访问的公共 HTTP 基地址（如 https://coord.example.com）：
        /// install.sh 内置它，一次性登录链接也按它拼接
        #[arg(long)]
        public_url: Option<String>,
        /// install.sh 写入 HZD_COORD_ADDR 的 gRPC 公网地址（缺省取 public-url 的主机名配 https）
        #[arg(long)]
        public_grpc_addr: Option<String>,
    },
    /// 签发 Auth Key（本机管理操作）
    Bootstrap {
        /// SQLite 数据库路径
        #[arg(long)]
        db: PathBuf,
        /// IPv4 地址段（FR-4）：首次初始化时固化到库，默认 100.96.0.0/16。
        #[arg(long)]
        cidr: Option<String>,
        /// 额外保留地址（可重复出现），从不分配给 Node。
        #[arg(long = "reserve")]
        reserve: Vec<std::net::Ipv4Addr>,
        /// 过期时间：Nd（如 7d、30d）或 RFC3339 时刻
        #[arg(long)]
        auth_key_expiry: String,
        /// 一次性 Key（默认可重复使用直至过期）
        #[arg(long)]
        once: bool,
        /// 预绑定 Tag（必填，可多次出现）：Auth Key 注册的 Node 不归属 User，身份即其 Tag
        #[arg(long = "tag", required = true)]
        tags: Vec<String>,
        /// 同时把该名字的 User 落库为 Admin（无需 Kanidm 即可种出第一个 Admin）
        #[arg(long)]
        admin: Option<String>,
        /// 同时签发 Relay Token（与 Auth Key 一样仅显示一次，供 hz-relay 使用）
        #[arg(long)]
        relay_token: bool,
        /// 只输出一行 JSON（脚本友好），不含人类可读说明
        #[arg(long)]
        json: bool,
    },
}

pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            db,
            cidr,
            reserve,
            listen,
            tls_cert,
            tls_key,
            http_listen,
            oidc_issuer,
            oidc_client_id,
            oidc_client_secret,
            oidc_redirect_uri,
            oidc_ca,
            login_node_ttl_days,
            metrics_listen,
            dist_dir,
            public_url,
            public_grpc_addr,
        } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(run_serve(ServeArgs {
                db,
                cidr,
                reserve,
                listen,
                tls_cert,
                tls_key,
                http_listen,
                oidc_issuer,
                oidc_client_id,
                oidc_client_secret,
                oidc_redirect_uri,
                oidc_ca,
                login_node_ttl_days,
                metrics_listen,
                dist_dir,
                public_url,
                public_grpc_addr,
            })),
        Command::Bootstrap {
            db,
            cidr,
            reserve,
            auth_key_expiry,
            once,
            tags,
            admin,
            relay_token,
            json,
        } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(run_bootstrap(
                db,
                RangeArgs { cidr, reserve },
                auth_key_expiry,
                once,
                tags,
                admin,
                relay_token,
                json,
            )),
    }
}

/// serve 子命令的参数集合；run_serve 只接收这一个参数。
struct ServeArgs {
    db: PathBuf,
    cidr: Option<String>,
    reserve: Vec<std::net::Ipv4Addr>,
    listen: String,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    http_listen: Option<String>,
    oidc_issuer: Option<String>,
    oidc_client_id: Option<String>,
    oidc_client_secret: Option<String>,
    oidc_redirect_uri: Option<String>,
    oidc_ca: Option<PathBuf>,
    login_node_ttl_days: i64,
    metrics_listen: Option<String>,
    dist_dir: Option<PathBuf>,
    public_url: Option<String>,
    public_grpc_addr: Option<String>,
}

async fn run_serve(args: ServeArgs) -> anyhow::Result<()> {
    let ServeArgs {
        db,
        cidr,
        reserve,
        listen,
        tls_cert,
        tls_key,
        http_listen,
        oidc_issuer,
        oidc_client_id,
        oidc_client_secret,
        oidc_redirect_uri,
        oidc_ca,
        login_node_ttl_days,
        metrics_listen,
        dist_dir,
        public_url,
        public_grpc_addr,
    } = args;
    let listen: std::net::SocketAddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("无效的监听地址 {listen}：{e}"))?;
    let store = Store::open_with_range(&db, RangeFlags { cidr, reserve }).await?;
    let mut config = ServeConfig::new(store, listen);
    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let cert = std::fs::read(&cert_path)?;
        let key = std::fs::read(&key_path)?;
        config.tls = Some(ServerTlsConfig::new().identity(Identity::from_pem(cert, key)));
    }
    config.login_node_ttl_secs = login_node_ttl_days * 86_400;

    let metrics_listen = metrics_listen
        .or_else(|| std::env::var("HZ_COORD_METRICS_LISTEN").ok())
        .unwrap_or_else(|| "127.0.0.1:9100".to_string());
    if !metrics_listen.eq_ignore_ascii_case("off") {
        config.metrics_listen = Some(
            metrics_listen
                .parse()
                .map_err(|e| anyhow::anyhow!("无效的 metrics 监听地址 {metrics_listen}：{e}"))?,
        );
    }

    // OIDC 与 HTTP 面参数也接受环境变量（容器/脚本部署）。
    let env_value = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let env_http_listen = env_value("HZ_COORD_HTTP_LISTEN");
    // 亚天级 TTL 的注入通道（有效期测试用 60 秒一类值）；缺省保持 flag 值。
    if let Some(secs) =
        env_value("HZ_COORD_LOGIN_NODE_TTL_SECS").and_then(|text| text.parse::<i64>().ok())
    {
        if secs <= 0 {
            anyhow::bail!("HZ_COORD_LOGIN_NODE_TTL_SECS 必须是正整数秒数");
        }
        config.login_node_ttl_secs = secs;
    }
    let issuer = oidc_issuer
        .or_else(|| env_value("HZ_COORD_OIDC_ISSUER"))
        .or_else(|| env_value("KANIDM_ISSUER"));
    if issuer.is_some() {
        let client_id = oidc_client_id
            .or_else(|| env_value("HZ_COORD_OIDC_CLIENT_ID"))
            .or_else(|| env_value("KANIDM_CLIENT_ID"))
            .ok_or_else(|| anyhow::anyhow!("配置了 OIDC 但缺少 client_id"))?;
        let client_secret = oidc_client_secret
            .or_else(|| env_value("HZ_COORD_OIDC_CLIENT_SECRET"))
            .or_else(|| env_value("KANIDM_CLIENT_SECRET"))
            .ok_or_else(|| anyhow::anyhow!("配置了 OIDC 但缺少 client secret"))?;
        let http_listen_addr: std::net::SocketAddr = http_listen
            .clone()
            .or_else(|| env_http_listen.clone())
            .ok_or_else(|| anyhow::anyhow!("配置了 OIDC 但缺少 --http-listen"))?
            .parse()
            .map_err(|e| anyhow::anyhow!("无效的 HTTP 监听地址：{e}"))?;
        let ca_cert = oidc_ca.or_else(|| env_value("HZ_COORD_OIDC_CA").map(PathBuf::from));
        let issuer: reqwest::Url = issuer
            .as_deref()
            .unwrap()
            .parse()
            .map_err(|e| anyhow::anyhow!("无效的 OIDC issuer：{e}"))?;
        // 回调地址必须与 IdP 注册的完全一致；测试在 loopback 上跑，缺省取监听端口。
        let redirect_uri =
            match oidc_redirect_uri.or_else(|| env_value("HZ_COORD_OIDC_REDIRECT_URI")) {
                Some(uri) => uri
                    .parse()
                    .map_err(|e| anyhow::anyhow!("无效的 OIDC 回调地址：{e}"))?,
                None => format!("http://127.0.0.1:{}/oidc/callback", http_listen_addr.port())
                    .parse()
                    .map_err(|e| anyhow::anyhow!("无效的 OIDC 回调地址：{e}"))?,
            };
        config.http_listen = Some(http_listen_addr);
        config.oidc = Some(OidcConfig {
            issuer,
            client_id,
            client_secret,
            redirect_uri,
            ca_cert,
        });
    }

    // 公共基地址同时用于 install.sh 与一次性登录链接（缺省时登录链接由回调地址推导）。
    let public_url = public_url.or_else(|| env_value("HZ_COORD_PUBLIC_URL"));
    config.public_url = public_url.clone();

    let dist_dir = dist_dir.or_else(|| env_value("HZ_COORD_DIST_DIR").map(PathBuf::from));
    if let Some(dir) = dist_dir {
        let url = public_url.ok_or_else(|| {
            anyhow::anyhow!("配置了 --dist-dir 但缺少 --public-url，install.sh 无法内置服务器地址")
        })?;
        let grpc_addr = public_grpc_addr
            .or_else(|| env_value("HZ_COORD_PUBLIC_GRPC_ADDR"))
            .or_else(|| default_grpc_addr(&url))
            .ok_or_else(|| {
                anyhow::anyhow!("无法从 --public-url 推导 gRPC 地址，请显式提供 --public-grpc-addr")
            })?;
        if config.http_listen.is_none() {
            let addr_text = http_listen
                .or_else(|| env_http_listen.clone())
                .ok_or_else(|| anyhow::anyhow!("配置了 --dist-dir 但缺少 --http-listen"))?;
            config.http_listen = Some(
                addr_text
                    .parse()
                    .map_err(|e| anyhow::anyhow!("无效的 HTTP 监听地址 {addr_text}：{e}"))?,
            );
        }
        config.dist = Some(DistConfig {
            dir,
            public_url: url,
            public_grpc_addr: grpc_addr,
        });
    }
    config.ops.db_path = Some(db);
    if let Some(path) = env_value("HZNET_BACKUP_SCRIPT") {
        config.ops.backup_script = PathBuf::from(path);
    }
    if let Some(path) = env_value("HZ_BACKUP_DIR") {
        config.ops.backup_dir = PathBuf::from(path);
    }
    if let Some(path) = env_value("HZNET_TLS_DIR") {
        config.ops.tls_dir = PathBuf::from(path);
    }
    let handle = serve(config).await?;
    tokio::signal::ctrl_c().await?;
    tracing::info!("ctrl-c received, hz-coord shutting down");
    handle.shutdown();
    handle.terminated().await;
    Ok(())
}

struct RangeArgs {
    cidr: Option<String>,
    reserve: Vec<std::net::Ipv4Addr>,
}

#[allow(clippy::too_many_arguments)] // CLI 入口参数即使用面；与库内 targeted allow 风格一致
async fn run_bootstrap(
    db: PathBuf,
    range: RangeArgs,
    auth_key_expiry: String,
    once: bool,
    tags: Vec<String>,
    admin: Option<String>,
    issue_relay_token: bool,
    json: bool,
) -> anyhow::Result<()> {
    if !crate::admin::has_tag(&tags) {
        anyhow::bail!(crate::admin::MISSING_TAG_MESSAGE);
    }
    let expires_at_unix = parse_expiry(&auth_key_expiry)?;
    let store = Store::open_with_range(
        &db,
        RangeFlags {
            cidr: range.cidr,
            reserve: range.reserve,
        },
    )
    .await?;
    if let Some(name) = &admin {
        store.upsert_user(name, true).await?;
    }
    let plaintext = store.create_auth_key(expires_at_unix, once, &tags).await?;
    let relay_token = if issue_relay_token {
        Some(store.create_relay_token().await?)
    } else {
        None
    };
    if json {
        let mut payload = serde_json::json!({
            "auth_key": plaintext,
            "expires_at_unix": expires_at_unix
        });
        if let Some(name) = &admin {
            payload["admin"] = serde_json::Value::String(name.clone());
        }
        if let Some(token) = relay_token {
            payload["relay_token"] = serde_json::Value::String(token);
        }
        println!("{payload}");
        return Ok(());
    }
    let expires_at = chrono::DateTime::from_timestamp(expires_at_unix, 0)
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| expires_at_unix.to_string());
    println!("Auth Key（仅此一次显示，请立即保存）：");
    println!("{plaintext}");
    println!("一次性：{}", if once { "是" } else { "否" });
    println!(
        "Tags：{}",
        if tags.is_empty() {
            "无".to_string()
        } else {
            tags.join(",")
        }
    );
    println!("有效期至：{expires_at}");
    if let Some(name) = &admin {
        println!("已把 User {name} 落库为 Admin（可凭其名下 Node 远程管理）");
    }
    if let Some(token) = relay_token {
        println!("Relay Token（仅此一次显示，请立即保存，供 hz-relay 使用）：");
        println!("{token}");
    }
    Ok(())
}

/// gRPC 公网地址缺省值：取 public-url 的主机名配 https（生产上 gRPC 与 HTTP
/// 面共用 coord.<域名>，gRPC 走 443，见 mvp-spec §2）。
fn default_grpc_addr(public_url: &str) -> Option<String> {
    let rest = public_url
        .strip_prefix("https://")
        .or_else(|| public_url.strip_prefix("http://"))?;
    let host = rest.split('/').next()?.split(':').next()?;
    (!host.is_empty()).then(|| format!("https://{host}"))
}

/// 支持 `7d`/`30d` 相对天数与 RFC3339 绝对时刻。
fn parse_expiry(text: &str) -> anyhow::Result<i64> {
    if let Some(days) = text.strip_suffix('d') {
        let days: i64 = days
            .parse()
            .map_err(|_| anyhow::anyhow!("无效的过期时间 {text}：天数应为数字，如 7d"))?;
        if days < 0 {
            anyhow::bail!("过期天数不能为负：{text}");
        }
        return Ok(chrono::Utc::now().timestamp() + days * 86_400);
    }
    let parsed = chrono::DateTime::parse_from_rfc3339(text)
        .map_err(|e| anyhow::anyhow!("无效的过期时间 {text}：{e}"))?;
    Ok(parsed.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_requires_a_tag() {
        let base = [
            "hz-coord",
            "bootstrap",
            "--db",
            "x.db",
            "--auth-key-expiry",
            "1d",
        ];
        assert!(Cli::try_parse_from(base).is_err());
        assert!(Cli::try_parse_from(base.into_iter().chain(["--tag", "server"])).is_ok());
    }

    #[test]
    fn grpc_addr_defaults_to_https_host_of_public_url() {
        assert_eq!(
            default_grpc_addr("https://coord.example.com:8443").as_deref(),
            Some("https://coord.example.com")
        );
        assert_eq!(
            default_grpc_addr("http://192.168.1.10:8080").as_deref(),
            Some("https://192.168.1.10")
        );
        assert_eq!(default_grpc_addr("ftp://coord.example.com"), None);
        assert_eq!(default_grpc_addr("https://"), None);
    }

    #[test]
    fn expiry_parsing_supports_relative_days_and_rfc3339() {
        let now = chrono::Utc::now().timestamp();
        assert_eq!(parse_expiry("0d").unwrap(), now);
        assert_eq!(parse_expiry("7d").unwrap(), now + 7 * 86_400);
        assert_eq!(
            parse_expiry("2027-01-02T03:04:05Z").unwrap(),
            chrono::DateTime::parse_from_rfc3339("2027-01-02T03:04:05Z")
                .unwrap()
                .timestamp()
        );
        assert!(parse_expiry("yesterday").is_err());
        assert!(parse_expiry("-3d").is_err());
    }
}
