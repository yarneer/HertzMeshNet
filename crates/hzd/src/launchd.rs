//! launchd 安装（mvp-spec §2）：hzd 本体保持前台运行、日志走 stderr，
//! 守护化交给 launchd。`install-launchd` 渲染 com.hznet.hzd.plist 写到
//! /Library/LaunchDaemons/ 并打印加载步骤；plist 内容与
//! packaging/launchd/com.hznet.hzd.plist 模板一致（#17 打包消费同一份形态）。
//! RunAtLoad + KeepAlive 让 hzd 开机自启、退出即拉起；状态目录取平台默认
//! /Library/Application Support/hzd（launchd 不继承 shell 环境变量，
//! 不依赖 HZD_STATE_DIR）。

use std::path::{Path, PathBuf};

pub const PLIST_LABEL: &str = "com.hznet.hzd";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.hznet.hzd.plist";
pub const LOG_PATH: &str = "/Library/Logs/hzd.log";

/// plist 渲染输入；program 是 hzd 的绝对路径（默认取当前可执行文件）。
pub struct LaunchdConfig {
    pub program: PathBuf,
    pub log_path: String,
}

impl LaunchdConfig {
    /// 纯函数，字面量可测。
    pub fn render(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n\
             <dict>\n\
             \x20   <key>Label</key>\n\
             \x20   <string>{PLIST_LABEL}</string>\n\
             \x20   <key>ProgramArguments</key>\n\
             \x20   <array>\n\
             \x20       <string>{program}</string>\n\
             \x20   </array>\n\
             \x20   <key>RunAtLoad</key>\n\
             \x20   <true/>\n\
             \x20   <key>KeepAlive</key>\n\
             \x20   <true/>\n\
             \x20   <key>StandardOutPath</key>\n\
             \x20   <string>{log}</string>\n\
             \x20   <key>StandardErrorPath</key>\n\
             \x20   <string>{log}</string>\n\
             </dict>\n\
             </plist>\n",
            program = self.program.display(),
            log = self.log_path,
        )
    }
}

/// `hzd install-launchd [--plist <路径>]`：渲染并写 plist，打印加载步骤。
/// 写 /Library/LaunchDaemons 需要 root；未提供 --plist 时直接给出失败提示。
pub fn install(plist_path: Option<&Path>) -> anyhow::Result<()> {
    let program = std::env::current_exe()
        .map_err(|error| anyhow::anyhow!("获取 hzd 可执行文件路径失败：{error}"))?;
    let config = LaunchdConfig {
        program,
        log_path: LOG_PATH.to_string(),
    };
    let target = plist_path.map_or_else(|| PathBuf::from(PLIST_PATH), Path::to_path_buf);
    std::fs::write(&target, config.render()).map_err(|error| {
        anyhow::anyhow!(
            "写入 {} 失败（需要 root：sudo hzd install-launchd）：{error}",
            target.display()
        )
    })?;
    println!("已写入 {}", target.display());
    println!("加载并启动（root）：");
    println!("  sudo launchctl load -w {}", target.display());
    println!("停止并卸载：");
    println!("  sudo launchctl unload -w {}", target.display());
    println!("日志：{LOG_PATH}（launchd 下 hzd 保持前台运行，输出重定向到该文件）");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_renders_label_program_runatload_keepalive_and_log_paths() {
        let config = LaunchdConfig {
            program: PathBuf::from("/usr/local/bin/hzd"),
            log_path: "/Library/Logs/hzd.log".to_string(),
        };
        let plist = config.render();
        assert!(
            plist.contains("<string>com.hznet.hzd</string>"),
            "Label 固定"
        );
        assert!(plist.contains("<string>/usr/local/bin/hzd</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n    <true/>"));
        assert!(plist.contains("<key>KeepAlive</key>\n    <true/>"));
        assert_eq!(
            plist
                .matches("<string>/Library/Logs/hzd.log</string>")
                .count(),
            2,
            "stdout 与 stderr 都落到日志文件"
        );
    }

    #[test]
    fn plist_bears_only_the_hznet_program_argument() {
        let config = LaunchdConfig {
            program: PathBuf::from("/usr/local/bin/hzd"),
            log_path: "/Library/Logs/hzd.log".to_string(),
        };
        let plist = config.render();
        let args_block = plist
            .split("<key>ProgramArguments</key>")
            .nth(1)
            .unwrap()
            .split("</array>")
            .next()
            .unwrap();
        assert_eq!(
            args_block.matches("<string>").count(),
            1,
            "ProgramArguments 只有 hzd 一个可执行文件，无额外参数"
        );
    }

    #[test]
    fn plist_renders_custom_paths_when_given() {
        let config = LaunchdConfig {
            program: PathBuf::from("/opt/hznet/sbin/hzd"),
            log_path: "/var/log/hzd.out".to_string(),
        };
        let plist = config.render();
        assert!(plist.contains("<string>/opt/hznet/sbin/hzd</string>"));
        assert!(plist.contains("<string>/var/log/hzd.out</string>"));
    }
}
