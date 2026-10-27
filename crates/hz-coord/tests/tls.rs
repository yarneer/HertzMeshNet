//! Seam B：TLS 一条——自签 CA + rcgen 服务端证书，客户端只信这份 CA，走完整注册。

use ed25519_dalek::{Signer, SigningKey};
use hz_coord::addr::AddressConfig;
use hz_coord::service::{ServeConfig, serve};
use hz_coord::store::Store;
use hz_proto::coord_client::CoordClient;
use hz_proto::{HelloRequest, PROTOCOL_VERSION, RegisterAuthKeyRequest};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity, ServerTlsConfig};

fn test_ca_and_server_cert() -> (String, String, String) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec!["hznet-test-ca".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let server_key = KeyPair::generate().unwrap();
    // CertificateParams::new 的入参就是 SAN DNS 名。
    let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    (ca_cert.pem(), server_cert.pem(), server_key.serialize_pem())
}

#[tokio::test]
async fn registration_succeeds_over_tls_with_trusted_ca() {
    let (ca_pem, cert_pem, key_pem) = test_ca_and_server_cert();

    let store = Store::open_in_memory(AddressConfig::default())
        .await
        .unwrap();
    let auth_key = store
        .create_auth_key(chrono::Utc::now().timestamp() + 3600, true, &[])
        .await
        .unwrap();

    let mut config = ServeConfig::new(store.clone(), "127.0.0.1:0".parse().unwrap());
    config.tls = Some(
        ServerTlsConfig::new()
            .identity(Identity::from_pem(cert_pem.as_bytes(), key_pem.as_bytes())),
    );
    let handle = serve(config).await.unwrap();

    let channel = Channel::from_shared(format!("https://localhost:{}", handle.local_addr.port()))
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(ca_pem.as_bytes()))
                .domain_name("localhost"),
        )
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = CoordClient::new(channel);

    let machine = SigningKey::generate(&mut rand_core::OsRng);
    let hello = client
        .hello(HelloRequest {
            protocol_version: PROTOCOL_VERSION,
            machine_key_pub: machine.verifying_key().to_bytes().to_vec(),
            hostname: "tls-node".to_owned(),
        })
        .await
        .unwrap()
        .into_inner();

    let response = client
        .register_with_auth_key(RegisterAuthKeyRequest {
            invite_code: None,
            challenge_nonce: hello.challenge_nonce.clone(),
            challenge_signature: machine.sign(&hello.challenge_nonce).to_bytes().to_vec(),
            auth_key,
            node_key_pub: [0u8; 32].to_vec(),
        })
        .await
        .unwrap()
        .into_inner();

    let node = response.node.unwrap();
    assert_eq!(node.name, "tls-node");
    assert_eq!(node.ipv4, "100.96.0.1");

    handle.shutdown();
    handle.terminated().await;
}
