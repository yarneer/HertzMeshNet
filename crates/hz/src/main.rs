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
    /// 注册本机（FR-1：带 --auth-key 用 Auth Key；否则走交互式登录 FR-2）
    Up {
        /// Auth Key 明文（hz-coord bootstrap 签发）；缺省时走交互式登录
        #[arg(long)]
        auth_key: Option<String>,
        /// Coordination Server 地址（默认读 HZD_COORD_ADDR，再退到内置占位地址）
        #[arg(long)]
        coord: Option<String>,
    },
    /// 重新交互式登录（已注册的 Node 重新归属到登录的 User，身份不变）
    Login {
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
        Command::Login { coord } => up(None, coord).await,
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

async fn up(auth_key: Option<String>, coord: Option<String>) -> std::process::ExitCode {
    let socket = paths::socket_path();
    let mut params = serde_json::json!({});
    if let Some(auth_key) = auth_key {
        params["auth_key"] = serde_json::Value::String(auth_key);
    }
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
    let result = match response {
        Response::Ok { result, .. } => result,
        Response::Error { error, .. } => {
            // hzd 侧的注册错误已经带"注册失败："上下文链，这里不再重复前缀。
            eprintln!("{error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    if result.get("login_url").is_some() {
        return interactive_login(result).await;
    }
    match serde_json::from_value::<RegisteredInfo>(result) {
        Ok(info) => {
            println!("注册成功");
            print_identity(&info);
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("无法解析 hzd 应答：{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// 交互式登录（FR-2）：打印一次性链接，然后等 hzd 轮询到登录结果。
async fn interactive_login(begin: serde_json::Value) -> std::process::ExitCode {
    let login_url = begin
        .get("login_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let expires_unix = begin.get("expires_unix").and_then(|v| v.as_i64());
    println!("一次性登录链接（仅显示一次，请在任意设备的浏览器中打开并登录）：");
    println!("{login_url}");
    match expires_unix.and_then(|unix| chrono::DateTime::from_timestamp(unix, 0)) {
        Some(time) => println!("有效期至：{}", time.to_rfc3339()),
        None => println!("链接将在短时间内过期"),
    }
    println!("等待登录完成……");

    let socket = paths::socket_path();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(600);
    loop {
        if tokio::time::Instant::now() >= deadline {
            eprintln!("等待登录超时，请重新执行 hz up");
            return std::process::ExitCode::FAILURE;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let request = Request::new(3, "login_poll", serde_json::json!({}));
        let response = match ipc::request(&socket, request).await {
            Ok(response) => response,
            Err(error) => {
                eprintln!("无法连接 hzd：{error:#}");
                return std::process::ExitCode::FAILURE;
            }
        };
        let result = match response {
            Response::Ok { result, .. } => result,
            Response::Error { error, .. } => {
                eprintln!("{error}");
                return std::process::ExitCode::FAILURE;
            }
        };
        let state = result.get("state").and_then(|v| v.as_str()).unwrap_or("");
        match state {
            "pending" | "idle" => continue,
            "failed" => {
                let error = result
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("未知错误");
                eprintln!("登录失败：{error}");
                return std::process::ExitCode::FAILURE;
            }
            "completed" => {
                match result
                    .get("node")
                    .and_then(|node| serde_json::from_value::<RegisteredInfo>(node.clone()).ok())
                {
                    Some(info) => {
                        println!("登录成功，已加入 HzNet");
                        print_identity(&info);
                        return std::process::ExitCode::SUCCESS;
                    }
                    None => {
                        eprintln!("hzd 返回的完成态缺少 Node 信息");
                        return std::process::ExitCode::FAILURE;
                    }
                }
            }
            _ => continue,
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
