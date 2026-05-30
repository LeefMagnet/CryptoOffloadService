//! SCEP CertRep 单元测试。

use crypto_offload_server::cryptooffload::v1::{KeyFormat, KeyKind, KeyLifetime};
use crypto_offload_server::crypto_scep;
use crypto_offload_server::key_store::KeyStore;
use crypto_offload_server::test_support::generate_rsa2048_der_cert;

#[test]
fn scep_build_failure_certrep() {
    let store = KeyStore::new();
    let (priv_pem, cert_der) = generate_rsa2048_der_cert().expect("key");

    let ca = store
        .import_key(
            KeyKind::Private as i32,
            KeyLifetime::Permanent as i32,
            KeyFormat::Pem as i32,
            &priv_pem,
            "ca",
            &cert_der,
            KeyFormat::Der as i32,
        )
        .expect("import ca");

    let access = store.access_key(&ca.key_id).expect("access");
    let certrep = crypto_scep::build_failure_certrep(
        access,
        "tx-123",
        &[1u8, 2, 3, 4],
        &[],
        2,
        "bad request",
    )
    .expect("build failure certrep");
    assert!(!certrep.is_empty());
}

#[test]
fn scep_build_success_certrep() {
    let store = KeyStore::new();
    let (ca_pem, ca_der) = generate_rsa2048_der_cert().expect("ca");
    let (_wrapper_pem, issued_der) = generate_rsa2048_der_cert().expect("issued");
    // wrapper 使用另一份 RSA 证书作为 envelop 接收方（测试用）
    let (wrapper_pem, wrapper_der) = generate_rsa2048_der_cert().expect("wrapper");

    let ca = store
        .import_key(
            KeyKind::Private as i32,
            KeyLifetime::Permanent as i32,
            KeyFormat::Pem as i32,
            &ca_pem,
            "ca",
            &ca_der,
            KeyFormat::Der as i32,
        )
        .expect("import ca");
    let _ = wrapper_pem;

    let access = store.access_key(&ca.key_id).expect("access");
    let certrep = crypto_scep::build_success_certrep(
        access,
        "tx-456",
        &[9u8, 8, 7, 6],
        &[],
        &issued_der,
        &wrapper_der,
    )
    .expect("build success certrep");
    assert!(!certrep.is_empty());
}
