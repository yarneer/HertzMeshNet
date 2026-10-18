use clap::{Parser, Subcommand};
use hz_core::ipc::{self, Request, Response};
use hz_core::paths;
use hz_core::status::NodeStatus;

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
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Status => status().await,
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
            Ok(NodeStatus::Registered(_)) => {
                println!("已加入 HzNet");
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
