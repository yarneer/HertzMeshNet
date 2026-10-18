//! FR-13 分发面：install.sh 占位符替换、manifest 与二进制下发、
//! 白名单外的平台/二进制一律 404。

use std::sync::Arc;

use hz_coord::addr::AddressConfig;
use hz_coord::authkey;
use hz_coord::http::{DistConfig, DistState, HttpState, serve_http};
use hz_coord::login::LoginRegistry;
use hz_coord::store::Store;
use sha2::{Digest, Sha256};

const HZD_X86: &[u8] = b"fake-hzd-linux-x86_64-binary";
const HZ_X86: &[u8] = b"fake-hz-linux-x86_64-binary";
const HZD_ARM_MAC: &[u8] = b"fake-hzd-darwin-arm64-binary";

/// HttpHandle 必须比请求活得久：Sender 一落，graceful shutdown 就开始。
async fn start_http(dist: Option<Arc<DistState>>) -> (String, hz_coord::http::HttpHandle) {
    let store = Store::open_in_memory(AddressConfig::default())
        .await
        .unwrap();
    let state = Arc::new(HttpState {
        oidc: None,
        logins: Arc::new(LoginRegistry::new()),
        store,
        login_node_ttl_secs: 90 * 86_400,
        dist,
    });
    let handle = serve_http("127.0.0.1:0".parse().unwrap(), state)
        .await
        .unwrap();
    (format!("http://{}", handle.local_addr), handle)
}

fn dist_with(platform_files: &[(&str, &str, &[u8])]) -> Arc<DistState> {
    let dir = tempfile::tempdir().unwrap();
    for (platform, name, bytes) in platform_files {
        let path = dir.path().join(platform).join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
    }
    let config = DistConfig {
        dir: dir.keep(),
        public_url: "https://coord.example.com:8443".to_string(),
        public_grpc_addr: "https://coord.example.com".to_string(),
    };
    Arc::new(DistState::build(&config).unwrap())
}

#[tokio::test]
async fn install_sh_is_served_with_server_urls_baked_in() {
    let (base, _handle) = start_http(Some(dist_with(&[("linux-x86_64", "hzd", HZD_X86)]))).await;
    let body = reqwest::get(format!("{base}/install.sh"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("COORD_URL=\"${HZNET_COORD_URL:-https://coord.example.com:8443}\""),
        "HTTP 分发面地址已写入，实际：{body}"
    );
    assert!(
        body.contains("GRPC_ADDR=\"${HZNET_COORD_ADDR:-https://coord.example.com}\""),
        "gRPC 地址已写入，实际：{body}"
    );
    assert!(!body.contains("@@HZNET_COORD"), "占位符全部被替换");
}

#[tokio::test]
async fn manifest_and_binaries_carry_matching_sha256() {
    let (base, _handle) = start_http(Some(dist_with(&[
        ("linux-x86_64", "hzd", HZD_X86),
        ("linux-x86_64", "hz", HZ_X86),
        ("darwin-arm64", "hzd", HZD_ARM_MAC),
    ])))
    .await;

    let manifest: serde_json::Value = reqwest::get(format!("{base}/dl/manifest.json"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let files = manifest["files"].as_object().unwrap();
    assert_eq!(files.len(), 3, "缺平台或缺二进制都会少条目：{manifest}");
    let entry = &files["linux-x86_64/hzd"];
    assert_eq!(
        entry["sha256"].as_str().unwrap(),
        authkey::hex(&Sha256::digest(HZD_X86))
    );
    assert_eq!(entry["size"].as_u64().unwrap(), HZD_X86.len() as u64);
    assert!(
        files.contains_key("darwin-arm64/hzd"),
        "每个存在的文件都有条目：{manifest}"
    );

    let response = reqwest::get(format!("{base}/dl/linux-x86_64/hz"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "application/octet-stream"
    );
    let bytes = response.bytes().await.unwrap();
    assert_eq!(&bytes[..], HZ_X86, "下发的就是 dist 目录里的那份文件");
}

#[tokio::test]
async fn unknown_platform_or_binary_is_not_found() {
    let (base, _handle) = start_http(Some(dist_with(&[("linux-x86_64", "hzd", HZD_X86)]))).await;
    for path in [
        "/dl/windows-x86_64/hzd",
        "/dl/linux-x86_64/hz-coord",
        "/dl/%2e%2e/etc/passwd",
        "/dl/missing-aarch64/hzd",
    ] {
        let response = reqwest::get(format!("{base}{path}")).await.unwrap();
        assert_eq!(response.status(), 404, "路径 {path} 应被拒绝");
    }
}

#[tokio::test]
async fn dist_routes_are_absent_without_dist_dir() {
    let (base, _handle) = start_http(None).await;
    let response = reqwest::get(format!("{base}/install.sh")).await.unwrap();
    assert_eq!(response.status(), 404);
    let response = reqwest::get(format!("{base}/dl/manifest.json"))
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    let response = reqwest::get(format!("{base}/healthz")).await.unwrap();
    assert_eq!(response.status(), 200);
}
