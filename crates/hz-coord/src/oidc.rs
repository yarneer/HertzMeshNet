//! OIDC 客户端（授权码 + PKCE S256）。整个系统里只有 Coordination Server 是
//! OIDC 客户端（FR-2 §2）；Node 侧永远只拿到登录 URL，不接触任何 IdP 凭证。
//!
//! 手工实现而非引入 openidconnect/oauth2 crate：所需面只有发现文档、授权 URL
//! 拼装、一次 token 交换和一次 userinfo 拉取，全部走带客户端认证的后通道 TLS，
//! 声明直接取自 userinfo 应答，无需本地校验 JWT 签名（信任源是 TLS + 客户端凭证，
//! 与 token 端点应答同级）。

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use reqwest::Url;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const ADMIN_GROUP: &str = "hznet_admins";

#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// 例如 https://auth.example.com（发现文档挂在
    /// /.well-known/openid-configuration）。
    pub issuer: Url,
    pub client_id: String,
    pub client_secret: String,
    /// 注册到 IdP 的回调地址，例如 http://127.0.0.1:8443/oidc/callback。
    pub redirect_uri: Url,
    /// 自签 IdP 的 CA 证书路径（测试环境）。
    pub ca_cert: Option<PathBuf>,
}

/// 发现文档里用到的三个端点；按字符串收下再解析成 Url（url::Url 不实现
/// Deserialize，边界处显式解析）。
#[derive(Debug, Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
}

pub struct OidcClient {
    config: OidcConfig,
    discovery: Endpoints,
    http: reqwest::Client,
}

/// 解析后的端点集合。
struct Endpoints {
    authorization_endpoint: Url,
    token_endpoint: Url,
    userinfo_endpoint: Url,
}

/// 一次登录的浏览器侧授权 URL。
pub struct AuthorizationRequest {
    pub url: Url,
}

/// userinfo 里信任的声明；其余字段在边界处丢弃。
#[derive(Debug, Clone)]
pub struct UserClaims {
    pub subject: String,
    pub preferred_username: String,
    pub groups: Vec<String>,
}

impl UserClaims {
    /// hznet_admins 成员即 Admin（FR-11）。Kanidm 的 groups claim 是 SPN 形式
    /// （name@domain），按前缀匹配以保持对域名配置不敏感。
    pub fn is_admin(&self) -> bool {
        self.groups
            .iter()
            .any(|group| group == ADMIN_GROUP || group.starts_with(&format!("{ADMIN_GROUP}@")))
    }
}

/// PKCE code verifier：43-128 字符的 URL 安全随机串（RFC 7636 §4.1）。
pub fn new_pkce_verifier() -> String {
    let mut bytes = [0u8; 48];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// S256 code challenge = BASE64URL(SHA256(verifier))。
pub fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn new_login_token(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}{}", crate::authkey::hex(&bytes))
}

impl OidcClient {
    pub async fn discover(config: OidcConfig) -> anyhow::Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(ca_path) = &config.ca_cert {
            let pem = std::fs::read(ca_path)
                .with_context(|| format!("读取 IdP CA 证书 {} 失败", ca_path.display()))?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .with_context(|| format!("解析 IdP CA 证书 {} 失败", ca_path.display()))?;
            builder = builder.add_root_certificate(cert);
        }
        let http = builder.build()?;

        // Kanidm 的发现文档挂在每个资源服务器名下
        // （{issuer}/oauth2/openid/<client>/.well-known/...），所以这里用字符串
        // 拼接保留 issuer 自带的路径，而不是整体替换。
        let discovery_url: Url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer.as_str().trim_end_matches('/')
        )
        .parse()
        .map_err(|error| anyhow!("OIDC 发现文档地址不合法：{error}"))?;
        let discovery: Discovery = http
            .get(discovery_url)
            .send()
            .await
            .and_then(|response| response.error_for_status())
            .map_err(|error| anyhow!("获取 OIDC 发现文档失败：{error}"))?
            .json()
            .await
            .map_err(|error| anyhow!("解析 OIDC 发现文档失败：{error}"))?;
        let parse = |field: &str, value: &str| {
            Url::parse(value).with_context(|| format!("发现文档的 {field} 不是合法 URL：{value}"))
        };
        let discovery = Endpoints {
            authorization_endpoint: parse(
                "authorization_endpoint",
                &discovery.authorization_endpoint,
            )?,
            token_endpoint: parse("token_endpoint", &discovery.token_endpoint)?,
            userinfo_endpoint: parse("userinfo_endpoint", &discovery.userinfo_endpoint)?,
        };
        Ok(Self {
            config,
            discovery,
            http,
        })
    }

    pub fn redirect_uri(&self) -> &Url {
        &self.config.redirect_uri
    }

    /// 跳过发现文档。单测把 token / userinfo 指到本机桩。
    #[cfg(test)]
    pub(crate) fn from_endpoints(
        config: OidcConfig,
        authorization_endpoint: Url,
        token_endpoint: Url,
        userinfo_endpoint: Url,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client");
        Self {
            config,
            discovery: Endpoints {
                authorization_endpoint,
                token_endpoint,
                userinfo_endpoint,
            },
            http,
        }
    }

    /// 构造浏览器要打开的授权 URL（授权码 + PKCE S256 + state + nonce）。
    /// state 填 login_id（回调据此找回 PendingLogin）；nonce 与 verifier 都是
    /// Begin 时生成并存在 PendingLogin 里的那一份。redirect_uri 用配置里
    /// 登记的 Node 登录回调。Admin Console 走 [`Self::authorization_request_to`]。
    pub fn authorization_request(
        &self,
        state: &str,
        nonce: &str,
        verifier: &str,
    ) -> AuthorizationRequest {
        self.authorization_request_to(&self.config.redirect_uri, state, nonce, verifier)
    }

    /// 同 [`Self::authorization_request`]，redirect_uri 由调用方给。
    /// Admin Console 传 `/admin/oidc/callback`（须在 Kanidm 另行登记）。
    pub fn authorization_request_to(
        &self,
        redirect_uri: &Url,
        state: &str,
        nonce: &str,
        verifier: &str,
    ) -> AuthorizationRequest {
        let mut url = self.discovery.authorization_endpoint.clone();
        url.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", self.config.client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", "openid profile groups"),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", pkce_challenge(verifier).as_str()),
            ("code_challenge_method", "S256"),
        ]);
        AuthorizationRequest { url }
    }

    /// 后通道：授权码换令牌，校验 id_token 的 nonce，再拉 userinfo 取声明。
    /// id_token 载荷与 userinfo 同源（本次 TLS 后通道应答），nonce 与 token
    /// 端点应答同级可信；不本地验 JWT 签名。任何一步失败都返回可读错误，
    /// 由回调页转述给浏览器前的 User。
    pub async fn exchange(
        &self,
        code: &str,
        verifier: &str,
        expected_nonce: &str,
    ) -> anyhow::Result<UserClaims> {
        self.exchange_at(&self.config.redirect_uri, code, verifier, expected_nonce)
            .await
    }

    /// 与 [`Self::exchange`] 相同，但 token 请求里的 redirect_uri 用调用方给的那条，
    /// 必须和授权请求一致（Admin Console 的回调在 `/admin/oidc/callback`）。
    pub async fn exchange_at(
        &self,
        redirect_uri: &Url,
        code: &str,
        verifier: &str,
        expected_nonce: &str,
    ) -> anyhow::Result<UserClaims> {
        let token_response = self
            .http
            .post(self.discovery.token_endpoint.clone())
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri.as_str()),
                ("code_verifier", verifier),
            ])
            .send()
            .await
            .map_err(|error| anyhow!("向 IdP 交换授权码失败：{error}"))?;
        let status = token_response.status();
        let body = token_response
            .text()
            .await
            .context("读取 token 端点应答失败")?;
        if !status.is_success() {
            bail!("IdP 拒绝了授权码交换（HTTP {status}）：{}", truncate(&body));
        }
        #[derive(Deserialize)]
        struct TokenBody {
            access_token: Option<String>,
            id_token: Option<String>,
        }
        let tokens: TokenBody =
            serde_json::from_str(&body).context("token 端点应答不是合法 JSON")?;
        let access_token = tokens
            .access_token
            .ok_or_else(|| anyhow!("token 端点应答缺少 access_token"))?;
        if let Some(id_token) = tokens.id_token {
            let nonce = id_token_nonce(&id_token)?;
            if nonce.as_deref() != Some(expected_nonce) {
                bail!("id_token 的 nonce 与本次登录不匹配，拒绝落定");
            }
        } else {
            bail!("token 端点应答缺少 id_token，无法校验 nonce");
        }

        let userinfo_response = self
            .http
            .get(self.discovery.userinfo_endpoint.clone())
            .bearer_auth(&access_token)
            .send()
            .await
            .map_err(|error| anyhow!("向 IdP 拉取 userinfo 失败：{error}"))?;
        let status = userinfo_response.status();
        let body = userinfo_response
            .text()
            .await
            .context("读取 userinfo 应答失败")?;
        if !status.is_success() {
            bail!(
                "IdP 拒绝了 userinfo 请求（HTTP {status}）：{}",
                truncate(&body)
            );
        }
        self.parse_userinfo(&body)
    }

    /// userinfo 是外部输入：只在边界解析一次，坏数据直接报错而不是静默降级。
    fn parse_userinfo(&self, body: &str) -> anyhow::Result<UserClaims> {
        #[derive(Deserialize)]
        struct Userinfo {
            sub: String,
            #[serde(default)]
            preferred_username: Option<String>,
            #[serde(default)]
            groups: Vec<String>,
        }
        let info: Userinfo = serde_json::from_str(body).context("userinfo 应答不是合法 JSON")?;
        if info.sub.is_empty() {
            bail!("userinfo 缺少 sub");
        }
        let subject = info.sub;
        let preferred_username = info
            .preferred_username
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| subject.clone());
        Ok(UserClaims {
            subject,
            preferred_username,
            groups: info.groups,
        })
    }
}

fn truncate(text: &str) -> String {
    text.chars().take(200).collect()
}

/// 取 JWT 载荷里的 nonce 声明；解析失败视为校验失败。
fn id_token_nonce(id_token: &str) -> anyhow::Result<Option<String>> {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        nonce: Option<String>,
    }
    let payload = id_token
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow!("id_token 不是合法 JWT"))?;
    let payload: Payload = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|error| anyhow!("id_token 载荷不是合法 base64url：{error}"))?,
    )
    .context("id_token 载荷不是合法 JSON")?;
    Ok(payload.nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_sha256_of_verifier_base64url() {
        // RFC 7636 附录 B 的向量（另与 python 的 base64url(sha256(v)) 互验过）。
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            pkce_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn admin_group_membership_matches_plain_and_spn_forms() {
        let claims = |groups: &[&str]| UserClaims {
            subject: "s".to_string(),
            preferred_username: "alice".to_string(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
        };
        assert!(claims(&["idm_all_persons@localhost", "hznet_admins@localhost"]).is_admin());
        assert!(claims(&["hznet_admins"]).is_admin());
        assert!(!claims(&["idm_all_persons@localhost", "hznet_users@localhost"]).is_admin());
        assert!(!claims(&["hznet_admins2@example.com"]).is_admin());
    }

    #[test]
    fn userinfo_parsing_requires_sub_and_falls_back_to_it_for_username() {
        let client_config = OidcConfig {
            issuer: "https://idm.example.com".parse().unwrap(),
            client_id: "c".to_string(),
            client_secret: "s".to_string(),
            redirect_uri: "http://127.0.0.1:1/oidc/callback".parse().unwrap(),
            ca_cert: None,
        };
        let client = OidcClient {
            config: client_config,
            discovery: Endpoints {
                authorization_endpoint: "https://idm.example.com/ui/oauth2".parse().unwrap(),
                token_endpoint: "https://idm.example.com/oauth2/token".parse().unwrap(),
                userinfo_endpoint: "https://idm.example.com/userinfo".parse().unwrap(),
            },
            http: reqwest::Client::new(),
        };
        let claims = client
            .parse_userinfo(r#"{"sub":"uuid-1","groups":["hznet_admins@localhost"]}"#)
            .unwrap();
        assert_eq!(claims.preferred_username, "uuid-1");
        assert!(claims.is_admin());
        assert!(client.parse_userinfo(r#"{"groups":[]}"#).is_err());
    }
}
