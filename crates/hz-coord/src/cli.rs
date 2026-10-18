//! `hz-coord` 子命令：serve（常驻 gRPC 服务）与 bootstrap（签发第一把 Auth Key）。

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tonic::transport::{Identity, ServerTlsConfig};

use crate::addr::AddressConfig;
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
            listen,
            tls_cert,
            tls_key,
        } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(run_serve(db, listen, tls_cert, tls_key)),
        Command::Bootstrap {
            db,
            auth_key_expiry,
            once,
            tags,
            relay_token,
            json,
        } => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(run_bootstrap(db, auth_key_expiry, once, tags, relay_token, json)),
    }
}

async fn run_serve(
    db: PathBuf,
    listen: String,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
) -> anyhow::Result<()> {
    let listen: std::net::SocketAddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("无效的监听地址 {listen}：{e}"))?;
    let store = Store::open(&db, AddressConfig::default()).await?;
    let mut config = ServeConfig::new(store, listen);
    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let cert = std::fs::read(&cert_path)?;
        let key = std::fs::read(&key_path)?;
        config.tls = Some(ServerTlsConfig::new().identity(Identity::from_pem(cert, key)));
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
    issue_relay_token: bool,
    json: bool,
) -> anyhow::Result<()> {
    let expires_at_unix = parse_expiry(&auth_key_expiry)?;
    let store = Store::open(&db, AddressConfig::default()).await?;
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
    if let Some(token) = relay_token {
        println!("Relay Token（仅此一次显示，请立即保存，供 hz-relay 使用）：");
        println!("{token}");
    }
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
