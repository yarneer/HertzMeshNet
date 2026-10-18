//! 自签 TLS（测试部署）：生成一次性 CA 与服务端证书，SAN 由调用方给定
//! （IP 或 DNS 名）。CA 的 PEM 写出后交给 Node 侧 HZD_RELAY_CA_PATH 信任。

use std::net::IpAddr;

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, SanType};
use tonic::transport::{Identity, ServerTlsConfig};

pub struct SelfSignedTls {
    pub server_config: ServerTlsConfig,
    pub ca_pem: String,
}

pub fn generate(sans: &[String]) -> anyhow::Result<SelfSignedTls> {
    let mut subject_alt_names = vec![SanType::IpAddress(IpAddr::from([127, 0, 0, 1]))];
    for san in sans {
        if let Ok(ip) = san.parse::<IpAddr>() {
            subject_alt_names.push(SanType::IpAddress(ip));
        } else {
            let dns = san
                .clone()
                .try_into()
                .map_err(|error| anyhow::anyhow!("无效的 DNS SAN {san}：{error}"))?;
            subject_alt_names.push(SanType::DnsName(dns));
        }
    }

    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::default();
    server_params.subject_alt_names = subject_alt_names;
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

    let server_config = ServerTlsConfig::new().identity(Identity::from_pem(
        server_cert.pem(),
        server_key.serialize_pem(),
    ));
    Ok(SelfSignedTls {
        server_config,
        ca_pem: ca_cert.pem(),
    })
}
