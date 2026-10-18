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
    Status,
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
        Command::Status => status().await,
        Command::Up { auth_key, coord } => up(auth_key, coord).await,
    }
}

async fn status() -> std::process::ExitCode {
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
        Response::Ok { result, .. } => match serde_json::from_value::<NodeStatus>(result) {
            Ok(NodeStatus::Unregistered) => {
                println!("未加入 HzNet");
                std::process::ExitCode::SUCCESS
            }
            Ok(NodeStatus::Registered(info)) => {
                println!("已加入 HzNet");
                print_identity(&info);
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
