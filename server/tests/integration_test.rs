//! gRPC 端到端集成测试：启动真实服务并验证 Key / Sign / CMS 全流程。

use crypto_offload_server::cryptooffload::v1::cms_service_client::CmsServiceClient;
use crypto_offload_server::cryptooffload::v1::key_service_client::KeyServiceClient;
use crypto_offload_server::cryptooffload::v1::scep_service_client::ScepServiceClient;
use crypto_offload_server::cryptooffload::v1::sign_service_client::SignServiceClient;
use crypto_offload_server::cryptooffload::v1::{
    BuildCmsRequest, BuildScepFailureCertRepRequest, BuildScepSuccessCertRepRequest,
    GetKeyInfoRequest, HashAlgorithm, ImportKeyRequest, KeyFormat, KeyKind, KeyLifetime,
    ListKeysRequest, SignAlgorithm, SignRequest, VerifyCmsRequest, VerifyRequest,
};
use crypto_offload_server::run_server;
use crypto_offload_server::test_support::{extract_public_pem, free_port, generate_rsa2048_der_cert, generate_rsa2048_pem};
use tokio::time::{sleep, Duration};

async fn start_test_server() -> String {
    let addr = free_port();
    tokio::spawn(async move {
        let _ = run_server(addr).await;
    });
    for _ in 0..50 {
        if tonic::transport::Channel::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .is_ok()
        {
            return format!("http://{addr}");
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("server failed to start on {addr}");
}

#[tokio::test]
async fn grpc_import_sign_verify_cms_flow() {
    let url = start_test_server().await;
    let channel = tonic::transport::Channel::from_shared(url)
        .unwrap()
        .connect()
        .await
        .expect("connect");

    let (priv_pem, cert_der) = generate_rsa2048_der_cert().expect("key");
    let pub_pem = extract_public_pem(&priv_pem).expect("pub");
    let payload = b"integration-test-payload".to_vec();

    let mut key_client = KeyServiceClient::new(channel.clone());
    let mut sign_client = SignServiceClient::new(channel.clone());
    let mut cms_client = CmsServiceClient::new(channel);

    let priv_import = key_client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Private as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data: priv_pem.clone(),
            label: "integration".into(),
            certificate_data: cert_der,
            certificate_format: KeyFormat::Der as i32,
        })
        .await
        .expect("import private")
        .into_inner();
    let priv_id = priv_import.metadata.expect("metadata").key_id;

    let pub_import = key_client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Public as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data: pub_pem,
            ..Default::default()
        })
        .await
        .expect("import public")
        .into_inner();
    let pub_id = pub_import.metadata.expect("metadata").key_id;

    let sign_resp = sign_client
        .sign(SignRequest {
            key_id: priv_id.clone(),
            data: payload.clone(),
            hash_algorithm: HashAlgorithm::HashSha256 as i32,
            sign_algorithm: SignAlgorithm::SignRsaPkcs1V15 as i32,
        })
        .await
        .expect("sign")
        .into_inner();
    assert!(!sign_resp.signature.is_empty());

    let verify_resp = sign_client
        .verify(VerifyRequest {
            key_id: pub_id.clone(),
            data: payload.clone(),
            signature: sign_resp.signature,
            hash_algorithm: HashAlgorithm::HashSha256 as i32,
            sign_algorithm: SignAlgorithm::SignRsaPkcs1V15 as i32,
        })
        .await
        .expect("verify")
        .into_inner();
    assert!(verify_resp.valid);

    let cms = cms_client
        .build(BuildCmsRequest {
            content: payload.clone(),
            sign_key_id: priv_id,
            detached: false,
            ..Default::default()
        })
        .await
        .expect("cms build")
        .into_inner();
    assert!(!cms.cms_der.is_empty());

    let cms_verify = cms_client
        .verify(VerifyCmsRequest {
            cms_der: cms.cms_der,
            verify_key_id: pub_id,
            ..Default::default()
        })
        .await
        .expect("cms verify")
        .into_inner();
    assert!(cms_verify.valid);

    let list = key_client
        .list_keys(ListKeysRequest {})
        .await
        .expect("list")
        .into_inner();
    assert!(list.keys.len() >= 2);
}

#[tokio::test]
async fn grpc_temporary_key_consumed() {
    let url = start_test_server().await;
    let channel = tonic::transport::Channel::from_shared(url)
        .unwrap()
        .connect()
        .await
        .expect("connect");

    let (priv_pem, _) = generate_rsa2048_pem().expect("key");
    let mut key_client = KeyServiceClient::new(channel.clone());
    let mut sign_client = SignServiceClient::new(channel);

    let imported = key_client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Private as i32,
            lifetime: KeyLifetime::Temporary as i32,
            format: KeyFormat::Pem as i32,
            key_data: priv_pem,
            ..Default::default()
        })
        .await
        .expect("import")
        .into_inner();
    let key_id = imported.metadata.expect("metadata").key_id;

    sign_client
        .sign(SignRequest {
            key_id: key_id.clone(),
            data: b"x".to_vec(),
            hash_algorithm: HashAlgorithm::HashSha256 as i32,
            ..Default::default()
        })
        .await
        .expect("sign");

    let info = key_client
        .get_key_info(GetKeyInfoRequest { key_id })
        .await;
    assert!(info.is_err(), "temporary key should be removed");
}

#[tokio::test]
async fn grpc_rejects_oversized_payload() {
    let url = start_test_server().await;
    let channel = tonic::transport::Channel::from_shared(url)
        .unwrap()
        .connect()
        .await
        .expect("connect");

    let (priv_pem, _) = generate_rsa2048_pem().expect("key");
    let mut key_client = KeyServiceClient::new(channel.clone());
    let mut sign_client = SignServiceClient::new(channel);

    let imported = key_client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Private as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data: priv_pem,
            ..Default::default()
        })
        .await
        .expect("import")
        .into_inner();
    let key_id = imported.metadata.expect("metadata").key_id;

    let huge = vec![0u8; 1024 * 1024 + 1];
    let err = sign_client
        .sign(SignRequest {
            key_id,
            data: huge,
            hash_algorithm: HashAlgorithm::HashSha256 as i32,
            ..Default::default()
        })
        .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn grpc_scep_failure_certrep() {
    let url = start_test_server().await;
    let channel = tonic::transport::Channel::from_shared(url)
        .unwrap()
        .connect()
        .await
        .expect("connect");

    let (ca_pem, ca_der) = generate_rsa2048_der_cert().expect("ca");
    let mut key_client = KeyServiceClient::new(channel.clone());
    let mut scep_client = ScepServiceClient::new(channel);

    let ca = key_client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Private as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data: ca_pem,
            label: "scep-ca".into(),
            certificate_data: ca_der,
            certificate_format: KeyFormat::Der as i32,
        })
        .await
        .expect("import ca")
        .into_inner();
    let ca_id = ca.metadata.expect("metadata").key_id;

    let resp = scep_client
        .build_failure_cert_rep(BuildScepFailureCertRepRequest {
            ca_key_id: ca_id,
            transaction_id: "integration-tx".into(),
            recipient_nonce: vec![1, 2, 3, 4],
            fail_info: 2,
            fail_info_text: "bad request".into(),
            ..Default::default()
        })
        .await
        .expect("build failure certrep")
        .into_inner();
    assert!(!resp.certrep_der.is_empty());
}

async fn grpc_sign_verify_roundtrip(
    channel: tonic::transport::Channel,
    priv_pem: Vec<u8>,
    pub_pem: Vec<u8>,
    cert_data: Vec<u8>,
    cert_format: KeyFormat,
    data: Vec<u8>,
    hash: i32,
    sign_alg: i32,
) {
    let mut key_client = KeyServiceClient::new(channel.clone());
    let mut sign_client = SignServiceClient::new(channel);

    let priv_import = key_client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Private as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data: priv_pem,
            certificate_data: cert_data,
            certificate_format: cert_format as i32,
            ..Default::default()
        })
        .await
        .expect("import private")
        .into_inner();
    let priv_id = priv_import.metadata.expect("metadata").key_id;

    let pub_import = key_client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Public as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data: pub_pem,
            ..Default::default()
        })
        .await
        .expect("import public")
        .into_inner();
    let pub_id = pub_import.metadata.expect("metadata").key_id;

    let sign_resp = sign_client
        .sign(SignRequest {
            key_id: priv_id,
            data: data.clone(),
            hash_algorithm: hash,
            sign_algorithm: sign_alg,
        })
        .await
        .expect("sign")
        .into_inner();

    let verify_resp = sign_client
        .verify(VerifyRequest {
            key_id: pub_id,
            data,
            signature: sign_resp.signature,
            hash_algorithm: hash,
            sign_algorithm: sign_resp.sign_algorithm,
        })
        .await
        .expect("verify")
        .into_inner();
    assert!(verify_resp.valid);
}

#[tokio::test]
async fn grpc_sign_verify_ed25519() {
    use crypto_offload_server::test_support::generate_ed25519_pem;

    let url = start_test_server().await;
    let channel = tonic::transport::Channel::from_shared(url)
        .unwrap()
        .connect()
        .await
        .expect("connect");

    let priv_pem = generate_ed25519_pem().expect("ed25519");
    let pub_pem = extract_public_pem(&priv_pem).expect("pub");

    grpc_sign_verify_roundtrip(
        channel,
        priv_pem,
        pub_pem,
        vec![],
        KeyFormat::Unspecified,
        b"grpc-ed25519".to_vec(),
        HashAlgorithm::Unspecified as i32,
        SignAlgorithm::SignEd25519 as i32,
    )
    .await;
}

#[tokio::test]
async fn grpc_sign_verify_sm2() {
    use crypto_offload_server::test_support::generate_sm2_pem;

    let url = start_test_server().await;
    let channel = tonic::transport::Channel::from_shared(url)
        .unwrap()
        .connect()
        .await
        .expect("connect");

    let (priv_pem, cert_pem) = match generate_sm2_pem() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("skip grpc_sign_verify_sm2: {e}");
            return;
        }
    };
    let pub_pem = extract_public_pem(&priv_pem).expect("pub");

    grpc_sign_verify_roundtrip(
        channel,
        priv_pem,
        pub_pem,
        cert_pem,
        KeyFormat::Pem,
        b"grpc-sm2".to_vec(),
        HashAlgorithm::Unspecified as i32,
        SignAlgorithm::SignSm2 as i32,
    )
    .await;
}

#[tokio::test]
async fn grpc_sign_verify_rsa_pss() {
    let url = start_test_server().await;
    let channel = tonic::transport::Channel::from_shared(url)
        .unwrap()
        .connect()
        .await
        .expect("connect");

    let (priv_pem, _) = generate_rsa2048_pem().expect("rsa");
    let pub_pem = extract_public_pem(&priv_pem).expect("pub");

    grpc_sign_verify_roundtrip(
        channel,
        priv_pem,
        pub_pem,
        vec![],
        KeyFormat::Unspecified,
        b"grpc-rsa-pss".to_vec(),
        HashAlgorithm::HashSha256 as i32,
        SignAlgorithm::SignRsaPss as i32,
    )
    .await;
}

#[tokio::test]
async fn grpc_scep_success_certrep() {
    let url = start_test_server().await;
    let channel = tonic::transport::Channel::from_shared(url)
        .unwrap()
        .connect()
        .await
        .expect("connect");

    let (ca_pem, ca_der) = generate_rsa2048_der_cert().expect("ca");
    let (_issued_pem, issued_der) = generate_rsa2048_der_cert().expect("issued");
    let (_wrapper_pem, wrapper_der) = generate_rsa2048_der_cert().expect("wrapper");

    let mut key_client = KeyServiceClient::new(channel.clone());
    let mut scep_client = ScepServiceClient::new(channel);

    let ca = key_client
        .import_key(ImportKeyRequest {
            kind: KeyKind::Private as i32,
            lifetime: KeyLifetime::Permanent as i32,
            format: KeyFormat::Pem as i32,
            key_data: ca_pem,
            certificate_data: ca_der,
            certificate_format: KeyFormat::Der as i32,
            ..Default::default()
        })
        .await
        .expect("import ca")
        .into_inner();
    let ca_id = ca.metadata.expect("metadata").key_id;

    let resp = scep_client
        .build_success_cert_rep(BuildScepSuccessCertRepRequest {
            ca_key_id: ca_id,
            transaction_id: "grpc-success-tx".into(),
            recipient_nonce: vec![1, 2, 3, 4],
            issued_cert_der: issued_der,
            wrapper_cert_der: wrapper_der,
            ..Default::default()
        })
        .await
        .expect("build success certrep")
        .into_inner();
    assert!(!resp.certrep_der.is_empty());
}
