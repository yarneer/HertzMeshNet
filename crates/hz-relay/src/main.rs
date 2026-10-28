//! `hz-relay` 子命令：serve（常驻中继）与 probe（用一次性 Machine Key 试探
//! 接入，未注册身份应被拒绝——部署自检用）。

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use ed25519_dalek::Signer;
use hz_proto::relay_client::RelayClient as RelayGrpcClient;
use hz_proto::relay_frame;
use hz_proto::{RelayFrame, RelayHello};
use rand_core::{OsRng, RngCore};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, ClientTlsConfig};
use x25519_dalek::{PublicKey as NodePublicKey, StaticSecret as NodeStaticSecret};

use hz_relay::tls::SelfSignedTls;

#[derive(Parser)]
#[command(name = "hz-relay", version, about = "HzNet Relay")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 启动 Relay
    Serve {
        /// 监听地址，如 0.0.0.0:8443
        #[arg(long)]
        listen: String,
        /// STUN 监听地址，可重复（FR-8 / #76：缺省 0.0.0.0:3478 与 0.0.0.0:3479，
        /// 两个端口让 Node 比较映射端口得到 NAT 形态）
        #[arg(long = "stun-listen", default_values_t = hz_relay::DEFAULT_STUN_LISTENS.iter().map(|listen| listen.to_string()))]
        stun_listen: Vec<String>,
        /// Coordination Server 地址（http:// 或 https://）
        #[arg(long)]
        coord: String,
        /// Relay Token（缺省读环境变量 HZ_RELAY_TOKEN）
        #[arg(long)]
        relay_token: Option<String>,
        /// TLS 证书 PEM（与 --tls-key 成对出现）
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        /// TLS 私钥 PEM
        #[arg(long)]
        tls_key: Option<PathBuf>,
        /// 自签 TLS（测试部署）：现场生成 CA 与服务端证书
        #[arg(long)]
        tls_self_signed: bool,
        /// 自签证书的 SAN（IP 或 DNS 名），可多次出现
        #[arg(long = "tls-san")]
        tls_san: Vec<String>,
        /// 自签模式下把 CA 证书 PEM 写到该路径（Node 侧 HZD_RELAY_CA_PATH 用）
        #[arg(long)]
        tls_ca_out: Option<PathBuf>,
        /// 每 Node 的 Relay 限速（Mbps，默认 10；环境变量 HZ_RELAY_RATE_MBPS）
        #[arg(long)]
        rate_limit_mbps: Option<u64>,
        /// Prometheus /metrics 监听地址（默认 127.0.0.1:9101；off 关闭）
        #[arg(long)]
        metrics_listen: Option<String>,
    },
    /// 用一次性身份接入 Relay（未注册的 Machine Key 应被拒绝）
    Probe {
        /// Relay 地址（http:// 或 https://）
        #[arg(long)]
        addr: String,
        /// 信任的 CA 证书 PEM（自签部署）
        #[arg(long)]
        ca: Option<PathBuf>,
        /// 呈报的 node id
        #[arg(long)]
        node_id: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    match cli.command {
        Command::Serve {
            listen,
            stun_listen,
            coord,
            relay_token,
            tls_cert,
            tls_key,
            tls_self_signed,
            tls_san,
            tls_ca_out,
            rate_limit_mbps,
            metrics_listen,
        } => runtime.block_on(run_serve(
            listen,
            stun_listen,
            coord,
            relay_token,
            tls_cert,
            tls_key,
            tls_self_signed,
            tls_san,
            tls_ca_out,
            rate_limit_mbps,
            metrics_listen,
        )),
        Command::Probe { addr, ca, node_id } => {
            std::process::exit(runtime.block_on(run_probe(addr, ca, node_id)));
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_serve(
    listen: String,
    stun_listen: Vec<String>,
    coord: String,
    relay_token: Option<String>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    tls_self_signed: bool,
    tls_san: Vec<String>,
    tls_ca_out: Option<PathBuf>,
    rate_limit_mbps: Option<u64>,
    metrics_listen: Option<String>,
) -> anyhow::Result<()> {
    let listen: std::net::SocketAddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("无效的监听地址 {listen}：{e}"))?;
    let relay_token = match relay_token {
        Some(token) => token,
        None => std::env::var("HZ_RELAY_TOKEN").map_err(|_| {
            anyhow::anyhow!("缺少 Relay Token（--relay-token 或环境变量 HZ_RELAY_TOKEN）")
        })?,
    };
    let rate_limit_mbps = rate_limit_mbps
        .or_else(|| std::env::var("HZ_RELAY_RATE_MBPS").ok()?.parse().ok())
        .unwrap_or(hz_relay::DEFAULT_RATE_LIMIT_MBPS);
    let metrics_listen = metrics_listen
        .or_else(|| std::env::var("HZ_RELAY_METRICS_LISTEN").ok())
        .unwrap_or_else(|| "127.0.0.1:9101".to_string());
    let metrics_listen = if metrics_listen.eq_ignore_ascii_case("off") {
        None
    } else {
        Some(
            metrics_listen
                .parse()
                .map_err(|e| anyhow::anyhow!("无效的 metrics 监听地址 {metrics_listen}：{e}"))?,
        )
    };

    let mut config = hz_relay::RelayConfig {
        listen,
        tls: None,
        coord_addr: coord,
        relay_token,
        rate_limit_mbps,
        metrics_listen,
    };
    tracing::info!(rate_limit_mbps, "per-node relay rate limit configured");
    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let cert = std::fs::read(&cert_path)?;
        let key = std::fs::read(&key_path)?;
        config.tls = Some(
            tonic::transport::ServerTlsConfig::new()
                .identity(tonic::transport::Identity::from_pem(cert, key)),
        );
    } else if tls_self_signed {
        let SelfSignedTls {
            server_config,
            ca_pem,
        } = hz_relay::tls::generate(&tls_san)?;
        if let Some(path) = tls_ca_out {
            std::fs::write(&path, &ca_pem)?;
            tracing::info!(path = %path.display(), "self-signed CA written");
        }
        config.tls = Some(server_config);
    } else {
        tracing::warn!("未配置 TLS，监听明文端口（仅限本地测试）");
    }

    let handle = hz_relay::serve_relay(config).await?;

    // STUN（FR-8 / #76）：与中继同一主机的 UDP 3478 与 3479，Node 从
    // WireGuard 共享 socket 来查询公网映射；两个目标比较映射端口得到
    // NAT 形态。socket 同样绑物理出口网卡（FR-7）。
    hz_relay::start_stun(&stun_listen).await?;

    tokio::signal::ctrl_c().await?;
    tracing::info!("ctrl-c received, hz-relay shutting down");
    handle.shutdown();
    handle.terminated().await;
    Ok(())
}

/// 返回进程退出码：0 = 被接受（不应发生，一次性身份未注册）；1 = 被拒绝或失败。
async fn run_probe(addr: String, ca: Option<PathBuf>, node_id: Option<String>) -> i32 {
    match try_probe(addr, ca, node_id).await {
        Ok(accepted) => {
            if accepted {
                println!("被接受（不应发生：一次性身份未注册）");
                0
            } else {
                1
            }
        }
        Err(error) => {
            eprintln!("接入失败：{error:#}");
            1
        }
    }
}

/// 返回 Ok(true) 表示流被接受。被拒绝时打印拒绝原因并返回 Ok(false)。
async fn try_probe(
    addr: String,
    ca: Option<PathBuf>,
    node_id: Option<String>,
) -> anyhow::Result<bool> {
    let mut endpoint = tonic::transport::Endpoint::from_shared(addr.clone())?
        .connect_timeout(std::time::Duration::from_secs(10));
    if endpoint.uri().scheme_str() == Some("https") {
        let mut tls = ClientTlsConfig::new();
        if let Some(path) = ca {
            let pem = std::fs::read_to_string(&path)?;
            tls = tls.ca_certificate(Certificate::from_pem(pem.as_bytes()));
        }
        endpoint = endpoint.tls_config(tls)?;
    }
    let channel = endpoint
        .connect()
        .await
        .map_err(|error| anyhow::anyhow!("连接 {addr} 失败：{error}"))?;
    let mut client = RelayGrpcClient::new(channel);

    let machine = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let node_secret = NodeStaticSecret::random_from_rng(OsRng);
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let hello = RelayHello {
        node_id: node_id.unwrap_or_else(|| "probe".to_string()),
        node_key_pub: NodePublicKey::from(&node_secret).to_bytes().to_vec(),
        machine_key_pub: machine.verifying_key().to_bytes().to_vec(),
        challenge_nonce: nonce.to_vec(),
        challenge_signature: machine.sign(&nonce).to_bytes().to_vec(),
    };

    let (frame_tx, frame_rx) = mpsc::channel::<RelayFrame>(2);
    frame_tx
        .send(RelayFrame {
            kind: Some(relay_frame::Kind::Hello(hello)),
        })
        .await?;
    let mut stream = client
        .relay_stream(ReceiverStream::new(frame_rx))
        .await
        .map_err(|error| anyhow::anyhow!("打开 RelayStream 失败：{error}"))?
        .into_inner();

    match stream.message().await? {
        Some(frame) => match frame.kind {
            Some(relay_frame::Kind::Error(error)) => {
                println!("被拒绝：{}（code={}）", error.message, error.code);
                Ok(false)
            }
            Some(_) => {
                println!("收到非错误帧，流未被拒绝");
                Ok(true)
            }
            None => {
                println!("收到空帧");
                Ok(true)
            }
        },
        None => {
            println!("流被关闭且未收到任何帧（未注册身份应收到拒绝）");
            Ok(false)
        }
    }
}
