use clap::{Parser, Subcommand};
use hz_core::coord_client::DEFAULT_COORD_ADDR;
use hz_core::ipc::{self, Request, Response};
use hz_core::paths;
use hz_core::status::{NodeStatus, RegisteredInfo};

#[derive(Parser)]
#[command(name = "hz", version, about = "HzNet 命令行工具")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 查看 Node 状态
    Status {
        /// 输出 hzd 应答的原始 JSON（脚本用）
        #[arg(long)]
        json: bool,
    },
    /// 用 Auth Key 注册本机（FR-1）
    Up {
        /// Auth Key 明文（hz-coord bootstrap 签发）
        #[arg(long)]
        auth_key: String,
        /// Coordination Server 地址（默认读 HZD_COORD_ADDR，再退到内置占位地址）
        #[arg(long)]
        coord: Option<String>,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Status { json } => status(json).await,
        Command::Up { auth_key, coord } => up(auth_key, coord).await,
    }
}

async fn status(json_output: bool) -> std::process::ExitCode {
    let socket = paths::socket_path();
    let request = Request::new(1, "status", serde_json::json!({}));
    let response = match ipc::request(&socket, request).await {
        Ok(response) => response,
        Err(error) => {
            eprintln!("无法连接 hzd：hzd 是否在运行？");
            eprintln!("详细信息：{error:#}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match response {
        Response::Ok { result, .. } if json_output => {
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            std::process::ExitCode::SUCCESS
        }
        Response::Ok { result, .. } => match serde_json::from_value::<NodeStatus>(result.clone()) {
            Ok(NodeStatus::Unregistered) => {
                println!("未加入 HzNet");
                std::process::ExitCode::SUCCESS
            }
            Ok(NodeStatus::Registered(info)) => {
                println!("已加入 HzNet");
                print_identity(&info);
                if let Some(suffix) = result.get("dns_suffix").and_then(|v| v.as_str()) {
                    println!("网内域名后缀：{suffix}");
                }
                print_peers(&result);
                std::process::ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("无法解析 hzd 应答：{error}");
                std::process::ExitCode::FAILURE
            }
        },
        Response::Error { error, .. } => {
            eprintln!("hzd 返回错误：{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn up(auth_key: String, coord: Option<String>) -> std::process::ExitCode {
    let socket = paths::socket_path();
    let mut params = serde_json::json!({ "auth_key": auth_key });
    if let Some(coord) = coord {
        params["coord_addr"] = serde_json::Value::String(coord);
    } else if std::env::var_os("HZD_COORD_ADDR").is_none() {
        eprintln!("未指定 --coord 且未设置 HZD_COORD_ADDR，将尝试默认地址 {DEFAULT_COORD_ADDR}");
    }
    let request = Request::new(2, "up", params);
    let response = match ipc::request(&socket, request).await {
        Ok(response) => response,
        Err(error) => {
            eprintln!("无法连接 hzd：hzd 是否在运行？");
            eprintln!("详细信息：{error:#}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match response {
        Response::Ok { result, .. } => match serde_json::from_value::<RegisteredInfo>(result) {
            Ok(info) => {
                println!("注册成功");
                print_identity(&info);
                std::process::ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("无法解析 hzd 应答：{error}");
                std::process::ExitCode::FAILURE
            }
        },
        Response::Error { error, .. } => {
            // hzd 侧的注册错误已经带"注册失败："上下文链，这里不再重复前缀。
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Network Map 里的对端（hzd 状态结果的 peers 字段）；更丰富的展示在 #15。
fn print_peers(result: &serde_json::Value) {
    let Some(peers) = result.get("peers").and_then(|v| v.as_array()) else {
        return;
    };
    if peers.is_empty() {
        println!("对端：无");
        return;
    }
    println!("对端：");
    for peer in peers {
        let field = |name: &str| {
            peer.get(name)
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string()
        };
        let endpoints = peer
            .get("endpoints")
            .and_then(|v| v.as_array())
            .map(|list| {
                list.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let handshake = peer
            .get("handshake_secs")
            .and_then(|v| v.as_u64())
            .map(|secs| format!("{secs} 秒前"))
            .unwrap_or_else(|| "未握手".to_string());
        println!(
            "  {} {} {} 端点[{}] 握手[{}]",
            field("name"),
            field("ipv4"),
            field("ipv6"),
            endpoints,
            handshake
        );
    }
}

fn print_identity(info: &RegisteredInfo) {
    println!("Node Name：{}", info.name);
    println!("IPv4：{}", info.ipv4);
    println!("IPv6：{}", info.ipv6);
    println!(
        "Tags：{}",
        if info.tags.is_empty() {
            "无".to_string()
        } else {
            info.tags.join(",")
        }
    );
    println!(
        "归属 User：{}",
        info.owner_user.as_deref().unwrap_or("无（Tag 注册）")
    );
    match info.expires_at_unix {
        Some(unix) => match chrono::DateTime::from_timestamp(unix, 0) {
            Some(time) => println!("有效期至：{}", time.to_rfc3339()),
            None => println!("有效期至：{unix}"),
        },
        None => println!("有效期：不过期"),
    }
}
