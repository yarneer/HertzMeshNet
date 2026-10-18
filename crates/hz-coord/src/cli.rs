//! `hz-coord` 子命令：serve（常驻 gRPC 服务）与 bootstrap（签发第一把 Auth Key）。

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tonic::transport::{Identity, ServerTlsConfig};

use crate::addr::AddressConfig;
use crate::oidc::OidcConfig;
use crate::service::{ServeConfig, serve};
use crate::store::Store;

#[derive(Parser)]
#[command(name = "hz-coord", version, about = "HzNet Coordination Server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 启动 Coordination Server
    Serve {
        /// SQLite 数据库路径
        #[arg(long)]
        db: PathBuf,
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
    },
    /// 签发 Auth Key（本机管理操作）
    Bootstrap {
        /// SQLite 数据库路径
        #[arg(long)]
        db: PathBuf,
        /// 过期时间：Nd（如 7d、30d）或 RFC3339 时刻
        #[arg(long)]
        auth_key_expiry: String,
        /// 一次性 Key（默认可重复使用直至过期）
        #[arg(long)]
        once: bool,
        /// 预绑定 Tag，可多次出现
        #[arg(long = "tag")]
        tags: Vec<String>,
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
        } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(run_serve(
                db,
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
            )),
        Command::Bootstrap {
            db,
            auth_key_expiry,
            once,
            tags,
            json,
        } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(run_bootstrap(db, auth_key_expiry, once, tags, json)),
    }
}

async fn run_serve(
    db: PathBuf,
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
) -> anyhow::Result<()> {
    let listen: std::net::SocketAddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("无效的监听地址 {listen}：{e}"))?;
    let store = Store::open(&db, AddressConfig::default()).await?;
    let mut config = ServeConfig::new(store.pool().clone(), listen);
    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let cert = std::fs::read(&cert_path)?;
        let key = std::fs::read(&key_path)?;
        config.tls = Some(ServerTlsConfig::new().identity(Identity::from_pem(cert, key)));
    }
    config.login_node_ttl_secs = login_node_ttl_days * 86_400;

    // OIDC 与 HTTP 面参数也接受环境变量（容器/脚本部署）。
    let env_value = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
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
            .or_else(|| env_value("HZ_COORD_HTTP_LISTEN"))
            .ok_or_else(|| anyhow::anyhow!("配置了 OIDC 但缺少 --http-listen"))?
            .parse()
            .map_err(|e| anyhow::anyhow!("无效的 HTTP 监听地址：{e}"))?;
        let ca_cert =
            oidc_ca.or_else(|| env_value("HZ_COORD_OIDC_CA").map(|path| PathBuf::from(path)));
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
    let handle = serve(config).await?;
    tokio::signal::ctrl_c().await?;
    tracing::info!("ctrl-c received, hz-coord shutting down");
    handle.shutdown();
    handle.terminated().await;
    Ok(())
}

async fn run_bootstrap(
    db: PathBuf,
    auth_key_expiry: String,
    once: bool,
    tags: Vec<String>,
    json: bool,
) -> anyhow::Result<()> {
    let expires_at_unix = parse_expiry(&auth_key_expiry)?;
    let store = Store::open(&db, AddressConfig::default()).await?;
    let plaintext = store.create_auth_key(expires_at_unix, once, &tags).await?;
    if json {
        println!(
            "{}",
            serde_json::json!({"auth_key": plaintext, "expires_at_unix": expires_at_unix})
        );
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
    Ok(())
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
