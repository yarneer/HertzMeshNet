//! 把语义化版本和 git 短 commit 写进编译期环境变量。
//! 源码包或无 git 时省略 commit，构建仍然成功。

fn main() {
    watch_git_head();
    let semver = std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION");
    let version = match short_commit() {
        Some(sha) => format!("{semver} ({sha})"),
        None => semver,
    };
    println!("cargo:rustc-env=HZ_VERSION_STRING={version}");
    println!("cargo:rustc-env=HZ_CLI_VERSION=hzd {version}");
}

fn short_commit() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8(output.stdout).ok()?;
    let sha = sha.trim();
    if sha.len() >= 7 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(sha.to_string())
    } else {
        None
    }
}

/// HEAD 指向分支时，提交只改 ref 文件，不改 HEAD 本身。两边都盯着，版本号才会跟着 commit 走。
fn watch_git_head() {
    let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--absolute-git-dir"])
        .stderr(std::process::Stdio::null())
        .output()
    else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let Ok(git_dir) = String::from_utf8(output.stdout) else {
        return;
    };
    let git_dir = std::path::PathBuf::from(git_dir.trim());
    let head = git_dir.join("HEAD");
    watch_file(&head);
    let Ok(contents) = std::fs::read_to_string(&head) else {
        return;
    };
    if let Some(reference) = contents.strip_prefix("ref: ") {
        watch_file(&git_dir.join(reference.trim()));
    }
}

fn watch_file(path: &std::path::Path) {
    if path.is_file() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}
