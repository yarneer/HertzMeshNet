//! `hz update`：从 Coordination Server 的分发面（`/dl`，与 install.sh 同源）
//! 或 GitHub Release 取 manifest，按 sha256 校验后替换 /usr/local/bin 下的
//! hzd 与 hz，并重启 hzd 服务。注册身份与服务配置（launchd plist /
//! /etc/default/hzd）原样保留。

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const GITHUB_DOWNLOAD: &str = "https://github.com/yarneer/HertzMeshNet/releases/latest/download";
const BIN_DIR: &str = "/usr/local/bin";
const BINARIES: [&str; 2] = ["hzd", "hz"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum From {
    /// Coordination Server 的 /dl（管理员控制发布节奏）
    Coord,
    /// GitHub Release 的最新正式版
    Github,
}

/// 下载源：manifest 与二进制的 URL 由它决定。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    Coord { base: String },
    Github,
}

impl Source {
    fn manifest_url(&self) -> String {
        match self {
            Self::Coord { base } => format!("{base}/dl/manifest.json"),
            Self::Github => format!("{GITHUB_DOWNLOAD}/manifest.json"),
        }
    }

    fn binary_url(&self, platform: &str, binary: &str) -> String {
        match self {
            Self::Coord { base } => format!("{base}/dl/{platform}/{binary}"),
            Self::Github => format!("{GITHUB_DOWNLOAD}/{binary}-{platform}"),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Coord { base } => format!("Coordination Server {base}"),
            Self::Github => "GitHub Release".to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Manifest {
    /// v0.3 起由 release 写入；更早的分发目录没有这个字段。
    version: Option<String>,
    files: BTreeMap<String, FileEntry>,
}

#[derive(Debug, Deserialize, Clone)]
struct FileEntry {
    sha256: String,
    size: u64,
}

/// 本机对应的 manifest 平台键（与 install.sh、release 资产同一写法）。
fn platform_key(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("linux", "x86_64") => Some("linux-x86_64"),
        ("linux", "aarch64") => Some("linux-aarch64"),
        _ => None,
    }
}

/// coord 的 gRPC 地址 → 分发面基址：保留 scheme 与 host[:port]，去掉路径。
/// 部署模板里两者同源（反代同一域名）；不同源时用 --coord 显式给 HTTP 地址。
fn coord_base(addr: &str) -> anyhow::Result<String> {
    let addr = addr.trim().trim_end_matches('/');
    let Some((scheme, rest)) = addr.split_once("://") else {
        bail!("coord 地址缺少 http(s)://：{addr}");
    };
    if scheme != "http" && scheme != "https" {
        bail!("coord 地址只支持 http / https：{addr}");
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        bail!("coord 地址缺少主机名：{addr}");
    }
    Ok(format!("{scheme}://{authority}"))
}

/// "0.4.0" / "v0.4.0" / "0.4.0 (abc1234)" → (0, 4, 0)。
fn parse_semver(text: &str) -> Option<(u64, u64, u64)> {
    let core = text.trim().trim_start_matches('v');
    let core = core.split([' ', '-', '+']).next()?;
    let mut parts = core.split('.').map(|part| part.parse::<u64>().ok());
    let version = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

/// 本机已装二进制与 manifest 的比对结论。
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// 已装二进制与 manifest 逐个 sha256 一致。
    UpToDate,
    /// 需要替换的二进制（按 BINARIES 顺序）。
    Update {
        to: String,
        binaries: Vec<&'static str>,
    },
    /// manifest 版本低于本机：不降级（--force 可越过）。
    WouldDowngrade { available: String },
    /// 版本号相同但文件不同（本机多半是本地构建）：不覆盖（--force 可越过）。
    LocalBuild,
    /// manifest 没有 version 字段：无从判断新旧（--force 可越过）。
    UnknownVersion,
}

fn plan(
    manifest_version: Option<&str>,
    current: &str,
    differing: Vec<&'static str>,
    force: bool,
) -> Plan {
    if differing.is_empty() {
        return Plan::UpToDate;
    }
    let to = manifest_version.unwrap_or("未知").to_string();
    if force {
        return Plan::Update {
            to,
            binaries: differing,
        };
    }
    let Some(available) = manifest_version.and_then(parse_semver) else {
        return Plan::UnknownVersion;
    };
    match parse_semver(current).map(|current| available.cmp(&current)) {
        Some(Ordering::Less) => Plan::WouldDowngrade { available: to },
        Some(Ordering::Equal) => Plan::LocalBuild,
        _ => Plan::Update {
            to,
            binaries: differing,
        },
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn installed_sha256(path: &Path) -> Option<String> {
    std::fs::read(path).ok().map(|bytes| sha256_hex(&bytes))
}

/// coord 地址来源：--coord > hzd 状态里注册时的 coord_addr > 状态目录的 registration.json。
async fn resolve_coord_addr(explicit: Option<String>) -> anyhow::Result<String> {
    if let Some(addr) = explicit {
        return Ok(addr);
    }
    let request = hz_core::ipc::Request::new(1, "status", serde_json::json!({}));
    if let Ok(hz_core::ipc::Response::Ok { result, .. }) =
        hz_core::ipc::request(&hz_core::paths::socket_path(), request).await
        && let Some(addr) = result["coord_addr"]
            .as_str()
            .filter(|addr| !addr.is_empty())
    {
        return Ok(addr.to_string());
    }
    let path = hz_core::paths::state_dir().join("registration.json");
    if let Ok(text) = std::fs::read_to_string(&path)
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(addr) = value["coord_addr"].as_str().filter(|addr| !addr.is_empty())
    {
        return Ok(addr.to_string());
    }
    bail!(
        "不知道 Coordination Server 地址：请用 --coord https://coord.<域名> 指定，或用 --from github"
    )
}

async fn fetch(client: &reqwest::Client, url: &str) -> anyhow::Result<Vec<u8>> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("下载 {url} 失败"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("下载 {url} 失败：HTTP {status}");
    }
    Ok(response.bytes().await?.to_vec())
}

pub async fn run(
    from: From,
    coord: Option<String>,
    check_only: bool,
    force: bool,
) -> std::process::ExitCode {
    match update(from, coord, check_only, force).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("更新失败：{error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn update(
    from: From,
    coord: Option<String>,
    check_only: bool,
    force: bool,
) -> anyhow::Result<()> {
    let Some(platform) = platform_key(std::env::consts::OS, std::env::consts::ARCH) else {
        bail!(
            "不支持的平台 {}/{}（hz update 支持 macOS arm64 与 Linux x86_64/aarch64；Android 走 App 内更新）",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    };
    let source = match from {
        From::Github => Source::Github,
        From::Coord => Source::Coord {
            base: coord_base(&resolve_coord_addr(coord).await?)?,
        },
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;
    let manifest_bytes = fetch(&client, &source.manifest_url()).await?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("{} 的 manifest.json 格式不对", source.describe()))?;

    let mut wanted = Vec::new();
    for binary in BINARIES {
        let key = format!("{platform}/{binary}");
        let Some(entry) = manifest.files.get(&key) else {
            bail!("{} 的 manifest 缺少 {key}", source.describe());
        };
        wanted.push((binary, entry.clone()));
    }
    let differing: Vec<&'static str> = wanted
        .iter()
        .filter(|(binary, entry)| {
            installed_sha256(&Path::new(BIN_DIR).join(binary)).as_deref()
                != Some(entry.sha256.as_str())
        })
        .map(|(binary, _)| *binary)
        .collect();

    let current = hz_core::version::semver();
    println!("当前版本：{}", hz_core::version::node_version());
    println!(
        "{} 提供：{}",
        source.describe(),
        manifest.version.as_deref().unwrap_or("未标版本")
    );
    let binaries = match plan(manifest.version.as_deref(), current, differing, force) {
        Plan::UpToDate => {
            println!("已是最新：{BIN_DIR} 下的 hzd 与 hz 与发布内容一致");
            return Ok(());
        }
        Plan::WouldDowngrade { available } => bail!(
            "{} 上是 {available}，低于本机 {current}，不降级。可改用 --from github，或让管理员更新服务器分发目录；确需降级加 --force",
            source.describe()
        ),
        Plan::LocalBuild => {
            println!(
                "本机已是 {current}，但二进制与发布内容不同（多半是本地构建），不覆盖；要换成发布版加 --force"
            );
            return Ok(());
        }
        Plan::UnknownVersion => bail!(
            "{} 的 manifest 没有版本号（分发目录早于 v0.3），无法判断新旧。可改用 --from github，或让管理员用新版本跑 scripts/deploy/upgrade.sh；确认要装加 --force",
            source.describe()
        ),
        Plan::Update { to, binaries } => {
            println!("可更新到 {to}（需替换：{}）", binaries.join("、"));
            binaries
        }
    };
    if check_only {
        println!("执行 sudo hz update 完成更新");
        return Ok(());
    }
    if unsafe { libc::geteuid() } != 0 {
        bail!("替换 {BIN_DIR} 下的二进制并重启 hzd 需要 root：sudo hz update");
    }

    let mut staged = Vec::new();
    for (binary, entry) in wanted
        .iter()
        .filter(|(binary, _)| binaries.contains(binary))
    {
        let url = source.binary_url(platform, binary);
        println!("下载 {url}");
        let bytes = fetch(&client, &url).await?;
        let got = sha256_hex(&bytes);
        if bytes.len() as u64 != entry.size || got != entry.sha256 {
            bail!(
                "{binary} 校验失败：期望 sha256 {}（{} 字节），实际 {got}（{} 字节）",
                entry.sha256,
                entry.size,
                bytes.len()
            );
        }
        staged.push((*binary, stage(binary, &bytes)?));
    }
    for (binary, temp) in &staged {
        let target = Path::new(BIN_DIR).join(binary);
        std::fs::rename(temp, &target)
            .with_context(|| format!("替换 {} 失败", target.display()))?;
        println!("已更新 {}", target.display());
    }
    restart_hzd()?;
    println!("完成：hzd 已重启，运行 hz status 确认");
    Ok(())
}

/// 写到目标目录里的临时文件（同一文件系统，rename 原子替换；正在运行的
/// 旧进程继续持有旧 inode）。
fn stage(binary: &str, bytes: &[u8]) -> anyhow::Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let path = Path::new(BIN_DIR).join(format!(".{binary}.update"));
    let mut file =
        std::fs::File::create(&path).with_context(|| format!("写 {} 失败", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    Ok(path)
}

fn command_ok(program: &str, args: &[&str]) -> bool {
    std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    done()
}

/// 与 install.sh 同一套重启：macOS 先等旧 hzd 恢复 DNS 后完全退出再加载。
#[cfg(target_os = "macos")]
fn restart_hzd() -> anyhow::Result<()> {
    const LABEL: &str = "system/com.hznet.hzd";
    const PLIST: &str = "/Library/LaunchDaemons/com.hznet.hzd.plist";
    let _ = command_ok("launchctl", &["bootout", LABEL]);
    if !wait_until(Duration::from_secs(15), || {
        !command_ok("launchctl", &["print", LABEL])
    }) {
        bail!(
            "旧 hzd 15 秒内未退出；查看 /Library/Logs/hzd.log 后执行 sudo launchctl bootstrap system {PLIST}"
        );
    }
    if !command_ok("launchctl", &["bootstrap", "system", PLIST]) {
        bail!("launchd 未能加载 hzd：sudo launchctl bootstrap system {PLIST}");
    }
    let running = wait_until(Duration::from_secs(10), || {
        std::process::Command::new("launchctl")
            .args(["print", LABEL])
            .output()
            .is_ok_and(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .any(|line| line.trim() == "state = running")
            })
    });
    if !running {
        bail!("hzd 已加载但 10 秒内未进入运行状态；查看 /Library/Logs/hzd.log");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn restart_hzd() -> anyhow::Result<()> {
    if !command_ok("systemctl", &["restart", "hzd"]) {
        bail!("systemctl restart hzd 失败；查看 journalctl -u hzd -n 50");
    }
    if !wait_until(Duration::from_secs(10), || {
        command_ok("systemctl", &["is-active", "--quiet", "hzd"])
    }) {
        bail!("hzd 10 秒内未进入运行状态；查看 journalctl -u hzd -n 50");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_keys_match_release_assets() {
        assert_eq!(platform_key("macos", "aarch64"), Some("darwin-arm64"));
        assert_eq!(platform_key("linux", "x86_64"), Some("linux-x86_64"));
        assert_eq!(platform_key("linux", "aarch64"), Some("linux-aarch64"));
        assert_eq!(platform_key("macos", "x86_64"), None);
        assert_eq!(platform_key("android", "aarch64"), None);
    }

    #[test]
    fn coord_base_keeps_scheme_and_authority() {
        assert_eq!(
            coord_base("https://coord.example.com").unwrap(),
            "https://coord.example.com"
        );
        assert_eq!(
            coord_base("http://10.0.0.1:8080/some/path/").unwrap(),
            "http://10.0.0.1:8080"
        );
        assert!(coord_base("coord.example.com").is_err());
        assert!(coord_base("grpc://coord.example.com").is_err());
    }

    #[test]
    fn urls_follow_coord_dl_and_github_asset_layouts() {
        let coord = Source::Coord {
            base: "https://coord.example.com".to_string(),
        };
        assert_eq!(
            coord.manifest_url(),
            "https://coord.example.com/dl/manifest.json"
        );
        assert_eq!(
            coord.binary_url("darwin-arm64", "hzd"),
            "https://coord.example.com/dl/darwin-arm64/hzd"
        );
        assert_eq!(
            Source::Github.binary_url("linux-x86_64", "hz"),
            format!("{GITHUB_DOWNLOAD}/hz-linux-x86_64")
        );
    }

    #[test]
    fn semver_parses_release_and_version_strings() {
        assert_eq!(parse_semver("0.4.0"), Some((0, 4, 0)));
        assert_eq!(parse_semver("v0.10.2"), Some((0, 10, 2)));
        assert_eq!(parse_semver("0.4.0 (952ad8f)"), Some((0, 4, 0)));
        assert_eq!(parse_semver("0.4"), None);
        assert_eq!(parse_semver("nope"), None);
    }

    #[test]
    fn plan_updates_only_when_files_differ_and_never_downgrades_silently() {
        assert_eq!(plan(Some("0.4.0"), "0.4.0", vec![], false), Plan::UpToDate);
        assert_eq!(
            plan(Some("0.5.0"), "0.4.0", vec!["hzd", "hz"], false),
            Plan::Update {
                to: "0.5.0".into(),
                binaries: vec!["hzd", "hz"]
            }
        );
        assert_eq!(
            plan(Some("0.4.0"), "0.4.0", vec!["hzd"], false),
            Plan::LocalBuild,
            "同版本号但内容不同（本地构建）时不覆盖"
        );
        assert_eq!(
            plan(Some("0.4.0"), "0.4.0", vec!["hzd"], true),
            Plan::Update {
                to: "0.4.0".into(),
                binaries: vec!["hzd"]
            }
        );
        assert_eq!(
            plan(Some("0.2.1"), "0.4.0", vec!["hzd"], false),
            Plan::WouldDowngrade {
                available: "0.2.1".into()
            }
        );
        assert_eq!(
            plan(None, "0.4.0", vec!["hzd"], false),
            Plan::UnknownVersion
        );
        assert_eq!(
            plan(None, "0.4.0", vec!["hzd"], true),
            Plan::Update {
                to: "未知".into(),
                binaries: vec!["hzd"]
            }
        );
    }

    #[test]
    fn manifest_without_version_still_parses() {
        let manifest: Manifest =
            serde_json::from_str(r#"{"files":{"darwin-arm64/hz":{"sha256":"ab","size":3}}}"#)
                .unwrap();
        assert!(manifest.version.is_none());
        assert_eq!(manifest.files["darwin-arm64/hz"].size, 3);
    }
}
