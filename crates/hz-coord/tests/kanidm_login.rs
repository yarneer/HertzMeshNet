//! FR-2 / FR-11 门禁：真实 Kanidm（docker，由 scripts/test/kanidm/run.sh 编排）。
//! `#[ignore]`：默认不跑（不联网是仓库默认，本测试例外由脚本显式启用）。
//! 五条票面 AC 全部在此断言：无头登录注册归属、链接一次性与短时效、
//! Node 状态目录无任何 IdP 凭证、hznet_admins 识别 Admin。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hz_coord::addr::AddressConfig;
use hz_coord::oidc::OidcConfig;
use hz_coord::service::{LOGIN_NODE_TTL_SECS, ServeConfig, ServeHandle, serve};
use hz_coord::store::Store;
use hz_core::coord_client::{LoginPoll, begin_interactive_login, poll_login_status};
use hz_core::keys::KeyStore;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Credentials {
    client_id: String,
    client_secret: String,
    issuer: String,
    alice_password: String,
    bob_password: String,
}

struct TestEnv {
    handle: ServeHandle,
    short_handle: ServeHandle,
    pool: sqlx::SqlitePool,
    issuer: String,
    http_port: u16,
    ca_path: PathBuf,
    credentials: Credentials,
}

// 失败原因（缺环境变量/连不上 IdP）原样带出，避免折叠成一句笼统的失败。
async fn build_env() -> Result<TestEnv, String> {
    let issuer = std::env::var("KANIDM_ISSUER").map_err(|_| "缺 KANIDM_ISSUER".to_string())?;
    let ca_path =
        PathBuf::from(std::env::var("KANIDM_CA").map_err(|_| "缺 KANIDM_CA".to_string())?);
    let http_port: u16 = std::env::var("KANIDM_HTTP_PORT_1")
        .map_err(|_| "缺 KANIDM_HTTP_PORT_1".to_string())?
        .parse()
        .map_err(|_| "KANIDM_HTTP_PORT_1 不是端口".to_string())?;
    let short_http_port: u16 = std::env::var("KANIDM_HTTP_PORT_2")
        .map_err(|_| "缺 KANIDM_HTTP_PORT_2".to_string())?
        .parse()
        .map_err(|_| "KANIDM_HTTP_PORT_2 不是端口".to_string())?;
    let credentials_text = std::fs::read_to_string(
        std::env::var("KANIDM_CREDENTIALS").map_err(|_| "缺 KANIDM_CREDENTIALS".to_string())?,
    )
    .map_err(|error| format!("读 KANIDM_CREDENTIALS 失败：{error}"))?;
    let credentials: Credentials = serde_json::from_str(last_json_line(&credentials_text))
        .map_err(|error| format!("credentials JSON 解析失败：{error}"))?;

    let oidc = |port: u16| -> Option<OidcConfig> {
        Some(OidcConfig {
            issuer: credentials.issuer.parse().ok()?,
            client_id: credentials.client_id.clone(),
            client_secret: credentials.client_secret.clone(),
            redirect_uri: format!("http://127.0.0.1:{port}/oidc/callback")
                .parse()
                .ok()?,
            ca_cert: Some(ca_path.clone()),
        })
    };

    let store = Store::open_in_memory(AddressConfig::default())
        .await
        .map_err(|error| format!("内存库打开失败：{error}"))?;
    let mut config = ServeConfig::new(
        store.clone(),
        "127.0.0.1:0"
            .parse()
            .map_err(|_| "监听地址解析失败".to_string())?,
    );
    config.http_listen = Some(SocketAddr::from(([127, 0, 0, 1], http_port)));
    config.oidc = Some(oidc(http_port).ok_or("OIDC 配置不完整")?);
    let handle = serve(config)
        .await
        .map_err(|error| format!("coord serve 启动失败：{error:#}"))?;

    let short_store = Store::open_in_memory(AddressConfig::default())
        .await
        .map_err(|error| format!("内存库打开失败：{error}"))?;
    let mut short_config = ServeConfig::new(
        short_store,
        "127.0.0.1:0"
            .parse()
            .map_err(|_| "监听地址解析失败".to_string())?,
    );
    short_config.http_listen = Some(SocketAddr::from(([127, 0, 0, 1], short_http_port)));
    short_config.oidc = Some(oidc(short_http_port).ok_or("OIDC 配置不完整")?);
    short_config.login_ttl = Duration::from_secs(2);
    let short_handle = serve(short_config)
        .await
        .map_err(|error| format!("短 TTL coord 启动失败：{error:#}"))?;

    Ok(TestEnv {
        handle,
        short_handle,
        pool: store.pool().clone(),
        issuer,
        http_port,
        ca_path,
        credentials,
    })
}

fn last_json_line(text: &str) -> &str {
    text.lines()
        .rev()
        .find(|line| line.starts_with('{'))
        .expect("credentials 文件里应有 JSON 行")
}

/// 无头浏览器驱动 Kanidm 登录：登录表单 → 授权/同意 → 回调。
/// entry 是 coord 的 /oidc/start 链接或直接的授权端点 URL。
/// 关键语义（实测）：登录后的 GET /ui/login* 会在已认证会话上 303 循环，
/// 所以登录表单一律直接 POST，绝不回 GET 表单页。
/// follow_callback=false 时停在回调跳转前，把授权码返回给调用方自行交换；
/// follow_callback=true 时跟进回调并校验 coord 的成功页。
async fn drive_browser(
    env: &TestEnv,
    username: &str,
    password: &str,
    entry: &str,
    follow_callback: bool,
) -> Option<String> {
    let client = http_client(env);

    enum Step {
        Get(String),
        // (action 路径, 表单字段)
        Post(String, Vec<(&'static str, String)>),
    }
    let mut step = Step::Get(if entry.contains("/oidc/start/") {
        client
            .get(entry)
            .send()
            .await
            .unwrap()
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .expect("/oidc/start 应 302 到授权端点")
    } else {
        entry.to_string()
    });

    let mut hops = 0;
    loop {
        hops += 1;
        assert!(hops <= 25, "浏览器驱动跳数超限");
        let (status, location, page) = match &step {
            Step::Get(url) => {
                if url.starts_with("http://127.0.0.1") {
                    let page = client.get(url).send().await.unwrap().text().await.unwrap();
                    assert!(page.contains("登录成功"), "回调应渲染成功页，实际：{page}");
                    return None;
                }
                let response = client.get(url).send().await.unwrap();
                let status = response.status();
                let location = redirect_location(&response);
                let page = if location.is_none() {
                    Some(response.text().await.unwrap())
                } else {
                    None
                };
                (status, location, page)
            }
            Step::Post(action, fields) => {
                let pairs: Vec<(&str, &str)> = fields
                    .iter()
                    .map(|(key, value)| (*key, value.as_str()))
                    .collect();
                let response = client
                    .post(format!("{}{}", env.issuer, action))
                    .form(&pairs)
                    .send()
                    .await
                    .unwrap();
                let status = response.status();
                let location = redirect_location(&response);
                let page = if location.is_none() {
                    Some(response.text().await.unwrap())
                } else {
                    None
                };
                (status, location, page)
            }
        };

        if let Some(location) = location {
            if location.starts_with("http://127.0.0.1") && !follow_callback {
                return location
                    .split("code=")
                    .nth(1)
                    .and_then(|rest| rest.split('&').next())
                    .map(str::to_owned);
            }
            step = Step::Get(absolute(env, &location));
            continue;
        }
        assert!(
            status.is_success(),
            "浏览器驱动收到 {status}（{:?}）",
            page.as_deref().map(|text| &text[..text.len().min(200)])
        );
        let page = page.expect("无重定向时应有页面正文");

        let action = form_action(&page).expect("页面应有表单").to_string();
        if action.ends_with("/login/begin") {
            step = Step::Post(
                action,
                vec![
                    ("username", username.to_string()),
                    ("password", password.to_string()),
                    ("remember_me", "1".to_string()),
                ],
            );
        } else if action.ends_with("/login/pw") {
            // begin 表单带上了口令但 UI 仍渲染口令页：直接补交口令表单。
            step = Step::Post(action, vec![("password", password.to_string())]);
        } else if action.ends_with("/oauth2/consent") {
            step = Step::Post(
                action,
                vec![(
                    "consent_token",
                    extract_hidden_value(&page, "consent_token"),
                )],
            );
        } else {
            panic!("浏览器驱动遇到未知表单 {action}");
        }
    }
}

fn redirect_location(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn absolute(env: &TestEnv, location: &str) -> String {
    if location.starts_with("http") {
        location.to_string()
    } else if let Some(stripped) = location.strip_prefix('/') {
        format!("{}/{}", env.issuer.trim_end_matches('/'), stripped)
    } else {
        format!("{}/ui/{}", env.issuer.trim_end_matches('/'), location)
    }
}

fn form_action(page: &str) -> Option<&str> {
    page.split("action=\"").nth(1)?.split('"').next()
}

fn extract_hidden_value(page: &str, name: &str) -> String {
    let after = page
        .split(&format!("name=\"{name}\""))
        .nth(1)
        .expect("表单缺字段");
    after
        .split("value=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("表单字段缺 value")
        .to_string()
}

/// Node 侧一次完整的交互式登录：申请链接 → 浏览器完成 → 轮询到注册结果。
/// relogin=true 复刻 hzd 的重新登录路径（#11/ADR-0005）：先暂存新 Node Key，
/// 新公钥随 BeginLogin 上行，登录完成后才落盘。
async fn node_login(
    env: &TestEnv,
    state_dir: &Path,
    hostname: &str,
    username: &str,
    relogin: bool,
) -> LoginOutcome {
    let coord_addr = format!("http://{}", env.handle.local_addr);
    let keys = KeyStore::load_or_create(state_dir).unwrap();
    let staged = relogin.then(|| keys.stage_node_rotation());
    let node_key_pub = staged
        .as_ref()
        .map(|(_, public)| *public)
        .unwrap_or_else(|| keys.node_public());
    let started = begin_interactive_login(state_dir, hostname, &coord_addr, node_key_pub)
        .await
        .expect("BeginLogin 应成功");
    drive_browser(
        env,
        username,
        password_for(env, username),
        &started.login_url,
        true,
    )
    .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "登录轮询超时");
        match poll_login_status(state_dir, hostname, &coord_addr, &started.login_id)
            .await
            .expect("LoginStatus 轮询不应出错")
        {
            LoginPoll::Pending => tokio::time::sleep(Duration::from_millis(300)).await,
            LoginPoll::Completed(info) => {
                if let Some((secret, public)) = staged {
                    keys.commit_node_rotation(state_dir, &secret)
                        .expect("Node Key 轮换落盘");
                    assert_eq!(public, keys.node_public());
                }
                persist_like_hzd(state_dir, &info);
                return LoginOutcome {
                    info,
                    login_url: started.login_url,
                };
            }
            LoginPoll::Failed(error) => panic!("登录失败：{error}"),
        }
    }
}

struct LoginOutcome {
    info: hz_core::status::RegisteredInfo,
    login_url: String,
}

fn password_for<'a>(env: &'a TestEnv, username: &str) -> &'a str {
    if username == "alice" {
        &env.credentials.alice_password
    } else {
        &env.credentials.bob_password
    }
}

/// 复刻 hzd 的落盘行为（hzd::save_registration 不是公共 API，形状一致即可）。
fn persist_like_hzd(state_dir: &Path, info: &hz_core::status::RegisteredInfo) {
    std::fs::write(
        state_dir.join("registration.json"),
        serde_json::to_string_pretty(info).unwrap(),
    )
    .unwrap();
}

async fn admin_flag(env: &TestEnv, user: &str) -> i64 {
    let row = sqlx::query("SELECT is_admin FROM users WHERE name = ?1")
        .bind(user)
        .fetch_one(&env.pool)
        .await
        .unwrap();
    use sqlx::Row;
    row.get::<i64, _>("is_admin")
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}

fn expected_state_files() -> [&'static str; 5] {
    [
        "machine-key",
        "machine-key.pub",
        "node-key",
        "node-key.pub",
        "registration.json",
    ]
}

#[tokio::test]
#[ignore = "需要真实 Kanidm：bash scripts/test/kanidm/run.sh"]
async fn kanidm_interactive_login_gate() {
    // 四条票面 AC 依序断言；一个运行时承载全部 hz-coord 实例（拆成多个
    // #[tokio::test] 会让先结束的测试带走服务端运行时）。
    let env = build_env().await.expect("测试环境初始化");

    // AC1：无头服务器 hz up → 另一设备完成登录 → 加入 HzNet 并归属该 User。
    let alice_dir = tempfile::tempdir().unwrap();
    KeyStore::load_or_create(alice_dir.path()).unwrap();
    let alice = node_login(&env, alice_dir.path(), "node-alice", "alice", false).await;
    assert_eq!(alice.info.owner_user.as_deref(), Some("alice"));
    assert_eq!(alice.info.name, "node-alice");
    let expected_expiry = chrono::Utc::now().timestamp() + LOGIN_NODE_TTL_SECS;
    let drift = (alice.info.expires_at_unix.unwrap() - expected_expiry).abs();
    assert!(drift < 120, "有效期应≈90 天，偏差 {drift} 秒");

    // AC4：hznet_admins 成员识别为 Admin，其他 User 不是。
    assert_eq!(admin_flag(&env, "alice").await, 1, "alice 应被识别为 Admin");
    let bob_dir = tempfile::tempdir().unwrap();
    KeyStore::load_or_create(bob_dir.path()).unwrap();
    let bob = node_login(&env, bob_dir.path(), "node-bob", "bob", false).await;
    assert_eq!(bob.info.owner_user.as_deref(), Some("bob"));
    assert_eq!(
        admin_flag(&env, "bob").await,
        0,
        "bob 不是 hznet_admins 成员"
    );

    // AC2：登录链接只能使用一次。
    let browser = http_client(&env);
    let replay = browser
        .get(&alice.login_url)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        replay.contains("已被使用"),
        "二次打开同一登录链接应被拒绝，实际页面：{replay}"
    );

    // AC2：短时间后过期（短 TTL 实例上轮询应拿到可读的过期终态）。
    let late_dir = tempfile::tempdir().unwrap();
    KeyStore::load_or_create(late_dir.path()).unwrap();
    let late_addr = format!("http://{}", env.short_handle.local_addr);
    let late_keys = KeyStore::load_or_create(late_dir.path()).unwrap();
    let late = begin_interactive_login(
        late_dir.path(),
        "node-late",
        &late_addr,
        late_keys.node_public(),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let error = loop {
        match poll_login_status(late_dir.path(), "node-late", &late_addr, &late.login_id)
            .await
            .unwrap()
        {
            LoginPoll::Failed(error) => break error,
            LoginPoll::Pending => tokio::time::sleep(Duration::from_millis(200)).await,
            LoginPoll::Completed(_) => panic!("过期链接不应完成注册"),
        }
    };
    assert!(
        error.contains("过期"),
        "过期链接应返回可读的过期提示，实际：{error}"
    );

    // AC3：Node 上不保存任何 IdP 凭证。测试自走一遍 OIDC 拿到真实 token，
    // 逐字节扫描两个 Node 的状态目录。
    let tokens = own_oidc_flow(&env, "alice").await;
    let access_token = tokens["access_token"].as_str().unwrap();
    let id_token = tokens["id_token"].as_str().unwrap();
    for dir in [alice_dir.path(), bob_dir.path()] {
        let names: Vec<String> = walk(dir)
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        for expected in expected_state_files() {
            assert!(
                names.iter().any(|name| name == expected),
                "{dir:?} 应包含 {expected}，实际：{names:?}"
            );
        }
        assert_eq!(
            names.len(),
            expected_state_files().len(),
            "状态目录不应多出文件"
        );
        for path in walk(dir) {
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !bytes
                    .windows(access_token.len())
                    .any(|w| w == access_token.as_bytes()),
                "{} 泄漏了 access_token",
                path.display()
            );
            assert!(
                !bytes
                    .windows(id_token.len())
                    .any(|w| w == id_token.as_bytes()),
                "{} 泄漏了 id_token",
                path.display()
            );
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains("access_token") && !text.contains("id_token"),
                "{} 不应出现 token 字段名",
                path.display()
            );
        }
    }

    env.handle.shutdown();
    env.handle.terminated().await;
    env.short_handle.shutdown();
    env.short_handle.terminated().await;
}

fn http_client(env: &TestEnv) -> reqwest::Client {
    let cert = reqwest::Certificate::from_pem(&std::fs::read(&env.ca_path).unwrap()).unwrap();
    reqwest::Client::builder()
        .add_root_certificate(cert)
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn base64_encode_urlsafe(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// 测试自持的一次 OIDC 流程（自己的 PKCE，不经 coord），返回 token 端点应答。
/// 用它拿到真实 access_token/id_token 作为状态目录扫描的特征串。
async fn own_oidc_flow(env: &TestEnv, username: &str) -> Value {
    use base64::Engine;
    use rand_core::RngCore;
    let mut seed = [0u8; 48];
    rand_core::OsRng.fill_bytes(&mut seed);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);
    use sha2::Digest;
    let challenge = base64_encode_urlsafe(&sha2::Sha256::digest(verifier.as_bytes()));

    let discovery: Value = http_client(env)
        .get(format!(
            "{}/.well-known/openid-configuration",
            env.credentials.issuer
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut url =
        reqwest::Url::parse(discovery["authorization_endpoint"].as_str().unwrap()).unwrap();
    url.query_pairs_mut().extend_pairs([
        ("response_type", "code"),
        ("client_id", env.credentials.client_id.as_str()),
        (
            "redirect_uri",
            &format!("http://127.0.0.1:{}/oidc/callback", env.http_port),
        ),
        ("scope", "openid profile groups"),
        ("state", "test-owned"),
        ("nonce", "test-owned-nonce"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);

    let code = drive_browser(
        env,
        username,
        &env.credentials.alice_password,
        url.as_str(),
        false,
    )
    .await
    .expect("自持流程应取到授权码");

    let token_endpoint = discovery["token_endpoint"].as_str().unwrap();
    let response = http_client(env)
        .post(token_endpoint)
        .basic_auth(
            &env.credentials.client_id,
            Some(&env.credentials.client_secret),
        )
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            (
                "redirect_uri",
                &format!("http://127.0.0.1:{}/oidc/callback", env.http_port),
            ),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(
        status.is_success(),
        "自持流程 token 交换失败（{status}）：{}",
        &body[..body.len().min(300)]
    );
    serde_json::from_str(&body).expect("token 端点应答应是 JSON")
}

/// #11 AC：User 被移出 hznet_admins 后，下次重新登录失去 Admin 权限；
/// 同时验证重新登录轮换 Node Key 而身份、NodeAddress、NodeName 不变（ADR-0005）。
/// 前置：run.sh 第一阶段已证明 alice 登录后 is_admin=1，随后执行
/// `kanidm idm group remove-members hznet_admins alice` 再运行本测试。
#[tokio::test]
#[ignore = "需要真实 Kanidm 且 alice 已被移出 hznet_admins：bash scripts/test/kanidm/run.sh 第二阶段"]
async fn admin_loss_on_relogin_gate() {
    use sqlx::Row;

    let env = build_env().await.expect("测试环境初始化");
    assert_eq!(
        std::env::var("KANIDM_ALICE_REMOVED").as_deref(),
        Ok("1"),
        "本测试必须在 alice 被移出 hznet_admins 之后运行"
    );

    let alice_dir = tempfile::tempdir().unwrap();
    KeyStore::load_or_create(alice_dir.path()).unwrap();
    let machine_key_pub = KeyStore::load_or_create(alice_dir.path())
        .unwrap()
        .machine_public()
        .to_vec();

    let node_row = || async {
        sqlx::query(
            "SELECT id, name, ipv4, node_key_pub, expires_at_unix FROM nodes WHERE machine_key_pub = ?1",
        )
        .bind(&machine_key_pub)
        .fetch_one(&env.pool)
        .await
        .unwrap()
    };

    let first = node_login(&env, alice_dir.path(), "node-alice", "alice", false).await;
    assert_eq!(
        admin_flag(&env, "alice").await,
        0,
        "移出 hznet_admins 后的登录必须失去 Admin（FR-11；移出前的 is_admin=1 由第一阶段证明）"
    );
    let before = node_row().await;

    let second = node_login(&env, alice_dir.path(), "node-alice", "alice", true).await;
    assert_eq!(
        admin_flag(&env, "alice").await,
        0,
        "重新登录不得复活 Admin 权限"
    );
    assert_eq!(
        second.info.node_id, first.info.node_id,
        "重新登录保持 Node 身份"
    );
    assert_eq!(second.info.name, first.info.name, "Node Name 不变");
    assert_eq!(second.info.ipv4, first.info.ipv4, "Node Address 不变");
    assert_eq!(second.info.owner_user.as_deref(), Some("alice"));

    let after = node_row().await;
    assert_eq!(row_str(&after, "id"), row_str(&before, "id"));
    assert_eq!(row_str(&after, "name"), row_str(&before, "name"));
    assert_eq!(row_str(&after, "ipv4"), row_str(&before, "ipv4"));
    assert_ne!(
        after.get::<Vec<u8>, _>("node_key_pub"),
        before.get::<Vec<u8>, _>("node_key_pub"),
        "重新登录必须轮换 Node Key"
    );
    assert_eq!(
        after.get::<Vec<u8>, _>("node_key_pub"),
        KeyStore::load_or_create(alice_dir.path())
            .unwrap()
            .node_public()
            .to_vec(),
        "coord 库里的 Node Key 必须与本地轮换后的公钥一致"
    );
    // 同一秒内完成的两次登录会得到相同的秒级时间戳，严格递增不成立；
    // 续期的语义是重置出完整的有效期窗口。
    let after_expiry = after.get::<i64, _>("expires_at_unix");
    let before_expiry = before.get::<i64, _>("expires_at_unix");
    let now = chrono::Utc::now().timestamp();
    assert!(
        after_expiry >= before_expiry && after_expiry > now + LOGIN_NODE_TTL_SECS - 120,
        "重新登录必须重置完整的有效期窗口（after={after_expiry} before={before_expiry} now={now}）"
    );

    env.handle.shutdown();
    env.handle.terminated().await;
}

fn row_str(row: &sqlx::sqlite::SqliteRow, column: &str) -> String {
    use sqlx::Row;
    row.get::<String, _>(column)
}
