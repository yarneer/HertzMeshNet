use clap::{Parser, Subcommand};
use hz_core::coord_client::DEFAULT_COORD_ADDR;
use hz_core::ipc::{self, Request, Response};
use hz_core::paths;
use hz_core::status::{NodeStatus, RegisteredInfo};
use std::path::PathBuf;

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
    /// Policy 管理（FR-10：push 整份替换 / get 查看 / rollback 回滚）
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Auth Key 管理（FR-11：签发与吊销，需要 Admin）
    Authkey {
        #[command(subcommand)]
        command: AuthkeyCommand,
    },
    /// Node 管理（FR-11：列表 / 改名 / 删除 / 吊销）
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// 探测一个对端：显示往返时延与当前路径（FR-12）
    Ping {
        /// 对端 Node Name 或 node id
        node: String,
    },
}

#[derive(Subcommand)]
enum AuthkeyCommand {
    /// 签发一把 Auth Key（需要 Admin；明文仅显示一次）
    Create {
        /// 过期时间：Nd（如 7d、30d）或 RFC3339 时刻
        #[arg(long)]
        expiry: String,
        /// 一次性 Key（用一次即作废）
        #[arg(long)]
        once: bool,
        /// 预绑定 Tag，可多次出现
        #[arg(long = "tag")]
        tags: Vec<String>,
    },
    /// 吊销一把 Auth Key（需要 Admin；之后不可再用于注册）
    Revoke {
        /// 签发时返回的 key id
        key_id: String,
    },
}

#[derive(Subcommand)]
enum NodeCommand {
    /// 列出 Node（Admin 看全部含已吊销；普通 User 只看自己名下）
    List {
        /// 输出 hzd 应答的原始 JSON（脚本用）
        #[arg(long)]
        json: bool,
    },
    /// 改名（Admin 任意 Node；普通 User 仅自己名下；新名须唯一）
    Rename {
        /// 目标 node id（hz node list 可查）
        node_id: String,
        /// 新 Node Name（自动按命名规则规范化）
        new_name: String,
    },
    /// 删除 Node（硬删；Admin 任意，普通 User 仅自己名下）
    Delete {
        /// 目标 node id
        node_id: String,
    },
    /// 吊销 Node（需要 Admin；立即从所有 Network Map 消失且无法通信）
    Revoke {
        /// 目标 node id
        node_id: String,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// 推送一份 TOML Policy（整份替换，校验失败整份拒绝）
    Push {
        /// TOML Policy 文件路径
        file: PathBuf,
    },
    /// 查看当前 Policy 与历史版本
    Get,
    /// 回滚到指定历史版本
    Rollback {
        /// 目标版本号（hz policy get 的历史列表里查）
        version: i64,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    restore_default_sigpipe();
    let cli = Cli::parse();
    match cli.command {
        Command::Status { json } => status(json).await,
        Command::Up { auth_key, coord } => up(auth_key, coord).await,
        Command::Login { coord } => up(None, coord).await,
        Command::Policy { command } => policy(command).await,
        Command::Authkey { command } => authkey(command).await,
        Command::Node { command } => node(command).await,
        Command::Ping { node } => ping(node).await,
    }
}

/// Rust 运行时默认忽略 SIGPIPE，`hz … | grep -q` 里读端先退出时 `println!` 会因
/// EPIPE panic。恢复默认行为，让 hz 像普通 Unix 工具一样被 SIGPIPE 静默终止。
fn restore_default_sigpipe() {
    #[cfg(unix)]
    // SAFETY: 在 main 起点、尚未产生任何输出时调用，只把 SIGPIPE 设回内核默认处置。
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

/// Policy 子命令：统一经本地 hzd 转发（挑战认证用本 Node 的 Machine Key）。
async fn policy(command: PolicyCommand) -> std::process::ExitCode {
    let socket = paths::socket_path();
    let request = match &command {
        PolicyCommand::Push { file } => {
            let content = match std::fs::read_to_string(file) {
                Ok(content) => content,
                Err(error) => {
                    eprintln!("读取 Policy 文件失败：{}：{error}", file.display());
                    return std::process::ExitCode::FAILURE;
                }
            };
            Request::new(4, "policy_push", serde_json::json!({ "content": content }))
        }
        PolicyCommand::Get => Request::new(5, "policy_get", serde_json::json!({})),
        PolicyCommand::Rollback { version } => Request::new(
            6,
            "policy_rollback",
            serde_json::json!({ "version": version }),
        ),
    };
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
            eprintln!("{error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match &command {
        PolicyCommand::Push { .. } => {
            println!(
                "推送成功，当前版本：{}",
                result["version"].as_i64().unwrap_or(0)
            );
            std::process::ExitCode::SUCCESS
        }
        PolicyCommand::Rollback { version } => {
            println!("已回滚到版本 {version}");
            std::process::ExitCode::SUCCESS
        }
        PolicyCommand::Get => print_policy(&result),
    }
}

/// Auth Key 子命令：统一经本地 hzd 转发（操作者 = 本 Node 归属的 User）。
async fn authkey(command: AuthkeyCommand) -> std::process::ExitCode {
    let socket = paths::socket_path();
    let request = match &command {
        AuthkeyCommand::Create { expiry, once, tags } => {
            let expires_unix = match parse_expiry(expiry) {
                Ok(unix) => unix,
                Err(error) => {
                    eprintln!("{error}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            Request::new(
                7,
                "authkey_create",
                serde_json::json!({
                    "expires_unix": expires_unix,
                    "single_use": once,
                    "tags": tags,
                }),
            )
        }
        AuthkeyCommand::Revoke { key_id } => {
            Request::new(8, "authkey_revoke", serde_json::json!({ "key_id": key_id }))
        }
    };
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
            eprintln!("{error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match &command {
        AuthkeyCommand::Create { expiry, .. } => {
            let key = result["auth_key"].as_str().unwrap_or_default();
            let key_id = result["key_id"].as_str().unwrap_or_default();
            println!("Auth Key（仅此一次显示，请立即保存）：");
            println!("{key}");
            println!("Key ID：{key_id}");
            if let Ok(unix) = parse_expiry(expiry) {
                if let Some(time) = chrono::DateTime::from_timestamp(unix, 0) {
                    println!("有效期至：{}", time.to_rfc3339());
                }
            }
            std::process::ExitCode::SUCCESS
        }
        AuthkeyCommand::Revoke { key_id } => {
            println!("已吊销 Auth Key {key_id}");
            std::process::ExitCode::SUCCESS
        }
    }
}

/// Node 管理子命令：同样经 hzd 转发；列表的可见范围由服务端按操作者裁剪。
async fn node(command: NodeCommand) -> std::process::ExitCode {
    let socket = paths::socket_path();
    let request = match &command {
        NodeCommand::List { .. } => Request::new(9, "node_list", serde_json::json!({})),
        NodeCommand::Rename { node_id, new_name } => Request::new(
            10,
            "node_rename",
            serde_json::json!({ "node_id": node_id, "new_name": new_name }),
        ),
        NodeCommand::Delete { node_id } => {
            Request::new(11, "node_delete", serde_json::json!({ "node_id": node_id }))
        }
        NodeCommand::Revoke { node_id } => {
            Request::new(12, "node_revoke", serde_json::json!({ "node_id": node_id }))
        }
    };
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
            eprintln!("{error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match &command {
        NodeCommand::List { json } => {
            if *json {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
                return std::process::ExitCode::SUCCESS;
            }
            print_node_table(&result)
        }
        NodeCommand::Rename { .. } => {
            println!(
                "改名成功，新 Node Name：{}",
                result["name"].as_str().unwrap_or("?")
            );
            std::process::ExitCode::SUCCESS
        }
        NodeCommand::Delete { node_id } => {
            println!("已删除 Node {node_id}");
            std::process::ExitCode::SUCCESS
        }
        NodeCommand::Revoke { node_id } => {
            println!("已吊销 Node {node_id}（立即从所有 Network Map 消失）");
            std::process::ExitCode::SUCCESS
        }
    }
}

/// `hz node list` 的表格输出：id / 名字 / 地址 / 归属与 Tag / 有效期 / 状态。
fn print_node_table(result: &serde_json::Value) -> std::process::ExitCode {
    let Some(nodes) = result.as_array() else {
        eprintln!("hzd 应答格式异常：{result}");
        return std::process::ExitCode::FAILURE;
    };
    if nodes.is_empty() {
        println!("没有可见的 Node");
        return std::process::ExitCode::SUCCESS;
    }
    println!("Node ID | Node Name | IPv4 | 归属 User | Tags | 有效期至 | 状态");
    for node in nodes {
        let field = |name: &str| {
            node.get(name)
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string()
        };
        let owner = node
            .get("owner_user")
            .and_then(|v| v.as_str())
            .unwrap_or("无（Tag 注册）");
        let tags = node
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .filter(|joined| !joined.is_empty())
            .unwrap_or_else(|| "无".to_string());
        let expires = node
            .get("expires_at_unix")
            .and_then(|v| v.as_i64())
            .and_then(|unix| chrono::DateTime::from_timestamp(unix, 0))
            .map(|t| t.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "不过期".to_string());
        let state = if node.get("revoked").and_then(|v| v.as_bool()) == Some(true) {
            "已吊销"
        } else {
            "在册"
        };
        println!(
            "{} | {} | {} | {} | {} | {} | {}",
            field("node_id"),
            field("name"),
            field("ipv4"),
            owner,
            tags,
            expires,
            state
        );
    }
    std::process::ExitCode::SUCCESS
}

/// 支持 `7d`/`30d` 相对天数与 RFC3339 绝对时刻（与 hz-coord bootstrap 同语法）。
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

fn print_policy(result: &serde_json::Value) -> std::process::ExitCode {
    let version = result["version"].as_i64().unwrap_or(0);
    if version == 0 {
        println!("尚无 Policy（全部 Node 全互通；推送第一份 Policy 后开始过滤）");
        return std::process::ExitCode::SUCCESS;
    }
    println!("当前 Policy（版本 {version}）：");
    println!("{}", result["content"].as_str().unwrap_or_default());
    println!("历史版本：");
    let mut history = result["history"].as_array().cloned().unwrap_or_default();
    history.sort_by_key(|entry| entry["version"].as_i64().unwrap_or(0));
    for entry in history.iter().rev() {
        let entry_version = entry["version"].as_i64().unwrap_or(0);
        let created = entry["created_at_unix"]
            .as_i64()
            .and_then(|unix| chrono::DateTime::from_timestamp(unix, 0))
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "?".to_string());
        let marker = if entry_version == version {
            "（当前）"
        } else {
            ""
        };
        println!("  {entry_version}  {created}{marker}");
    }
    std::process::ExitCode::SUCCESS
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
            Ok(NodeStatus::Expired(info)) => {
                if result.get("revoked").and_then(|v| v.as_bool()) == Some(true) {
                    println!("已吊销：本 Node 已被 Admin 吊销，无法通信；重新加入需以新身份注册");
                } else {
                    println!("已过期，请重新执行 hz up 登录");
                }
                print_identity(&info);
                if let Some(suffix) = result.get("dns_suffix").and_then(|v| v.as_str()) {
                    println!("网内域名后缀：{suffix}");
                }
                print_peers(&result);
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

/// Endpoint 字符串的族别判定（v6 的 SocketAddr 文本带方括号，但 v4 也带端口冒号，
/// 不能用 contains(':') 判别）。
fn endpoint_is_v6(endpoint: &str) -> bool {
    endpoint
        .parse::<std::net::SocketAddr>()
        .is_ok_and(|addr| addr.is_ipv6())
}

/// `hz ping`（FR-12）：显示往返时延与这次探测所走的路径。
async fn ping(node: String) -> std::process::ExitCode {
    let socket = paths::socket_path();
    let request = Request::new(4, "ping", serde_json::json!({ "node": node }));
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
            eprintln!("{error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let name = result.get("name").and_then(|v| v.as_str()).unwrap_or("?");
    let rtt_ms = result
        .get("rtt_ms")
        .and_then(|v| v.as_f64())
        .unwrap_or(f64::NAN);
    let endpoint = result.get("endpoint").and_then(|v| v.as_str());
    let path_label = match result.get("path").and_then(|v| v.as_str()) {
        Some("direct") => match endpoint {
            Some(endpoint) => format!(
                "Direct Path（IPv{} {}）",
                if endpoint_is_v6(endpoint) { 6 } else { 4 },
                endpoint
            ),
            None => "Direct Path".to_string(),
        },
        Some("relay") => "Relayed Path".to_string(),
        _ => "未知".to_string(),
    };
    println!("{name} 往返 {rtt_ms:.1} ms，路径 {path_label}");
    std::process::ExitCode::SUCCESS
}

/// Network Map 里的对端（hzd 状态结果的 peers 字段）；表格式展示
/// Node Name / Node Address / 路径 / Endpoint / 最近握手（FR-12）。
fn print_peers(result: &serde_json::Value) {
    let Some(peers) = result.get("peers").and_then(|v| v.as_array()) else {
        return;
    };
    if peers.is_empty() {
        println!("对端：无");
        return;
    }
    println!("对端：");
    println!("  Node Name | Node Address | 路径 | Endpoint | 最近握手");
    for peer in peers {
        let field = |name: &str| {
            peer.get(name)
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string()
        };
        let address = format!("{} / {}", field("ipv4"), field("ipv6"));
        let endpoint = peer
            .get("endpoint")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let path = match peer.get("path").and_then(|v| v.as_str()) {
            Some("direct") if endpoint_is_v6(&endpoint) => "Direct Path (IPv6)",
            Some("direct") => "Direct Path (IPv4)",
            Some("relay") => "Relayed Path",
            _ => "未知",
        };
        let handshake = peer
            .get("handshake_secs")
            .and_then(|v| v.as_u64())
            .map(|secs| format!("{secs} 秒前"))
            .unwrap_or_else(|| "从未".to_string());
        println!(
            "  {} | {} | {} | {} | {}",
            field("name"),
            address,
            path,
            endpoint,
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
