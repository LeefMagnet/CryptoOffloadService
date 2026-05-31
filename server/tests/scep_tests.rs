//! SCEP CertRep 与 PKIO（3DES EnvelopedData）单元测试。
//!
//! OpenSSL 3.x 下 3DES 在 **legacy provider** 中；Debian bookworm 等需安装
//! `openssl-provider-legacy`，否则 `parse_request` / `generate_scep_pkio` 会失败。

use crypto_offload_server::cryptooffload::v1::{KeyFormat, KeyKind, KeyLifetime};
use crypto_offload_server::crypto_scep;
use crypto_offload_server::key_store::KeyStore;
use crypto_offload_server::openssl_init;
use crypto_offload_server::test_support::{generate_rsa2048_der_cert, generate_scep_pkio};
use openssl::x509::X509;

fn init_scep_test_openssl() {
    openssl_init::init();
    assert!(
        openssl_init::legacy_provider_loaded(),
        "OpenSSL 3 legacy provider not loaded — SCEP 3DES EnvelopedData requires it \
         (e.g. apt install openssl-provider-legacy on Debian bookworm)"
    );
}

fn import_ca(store: &KeyStore, label: &str) -> (String, Vec<u8>) {
    let (ca_pem, ca_der) = generate_rsa2048_der_cert().expect("ca key");
    let meta = store
        .import_key(
            KeyKind::Private as i32,
            KeyLifetime::Permanent as i32,
            KeyFormat::Pem as i32,
            &ca_pem,
            label,
            &ca_der,
            KeyFormat::Der as i32,
        )
        .expect("import ca");
    (meta.key_id, ca_der)
}

#[test]
fn scep_parse_request_3des_pkio() {
    init_scep_test_openssl();

    let store = KeyStore::new();
    let (ca_id, ca_der) = import_ca(&store, "scep-ca-parse");
    let ca_cert = X509::from_der(&ca_der).expect("ca cert");

    let (pkio_der, expected_csr, expected_wrapper) =
        generate_scep_pkio(&ca_cert).expect("build 3DES PKIO fixture");
    assert!(!pkio_der.is_empty(), "PKIO must be non-empty DER");

    let access = store.access_key(&ca_id).expect("access ca");
    let (csr_der, wrapper_cert_der) =
        crypto_scep::parse_request(&pkio_der, access).expect("parse 3DES SCEP PKIO");

    assert_eq!(csr_der, expected_csr, "decrypted CSR must match fixture");
    assert_eq!(
        wrapper_cert_der, expected_wrapper,
        "wrapper cert from outer SignedData must match fixture"
    );
}

#[test]
fn scep_parse_then_build_success_3des_roundtrip() {
    init_scep_test_openssl();

    let store = KeyStore::new();
    let (ca_id, ca_der) = import_ca(&store, "scep-ca-roundtrip");
    let ca_cert = X509::from_der(&ca_der).expect("ca cert");
    let (_issued_pem, issued_der) = generate_rsa2048_der_cert().expect("issued cert");

    let (pkio_der, _expected_csr, _expected_wrapper) =
        generate_scep_pkio(&ca_cert).expect("PKIO fixture");

    let access = store.access_key(&ca_id).expect("access ca");
    let (csr_der, wrapper_cert_der) =
        crypto_scep::parse_request(&pkio_der, access).expect("parse PKIO");
    assert!(!csr_der.is_empty());

    let access = store.access_key(&ca_id).expect("access ca again");
    let certrep = crypto_scep::build_success_certrep(
        access,
        "tx-roundtrip-3des",
        &[0xAA, 0xBB, 0xCC, 0xDD],
        &[],
        &issued_der,
        &wrapper_cert_der,
    )
    .expect("build SUCCESS CertRep with 3DES Envelop");
    assert!(!certrep.is_empty());
}

#[test]
fn scep_build_failure_certrep() {
    init_scep_test_openssl();

    let store = KeyStore::new();
    let (ca_id, _ca_der) = import_ca(&store, "scep-ca-failure");

    let access = store.access_key(&ca_id).expect("access");
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
    init_scep_test_openssl();

    let store = KeyStore::new();
    let (ca_id, _ca_der) = import_ca(&store, "scep-ca-success");
    let (_wrapper_pem, wrapper_der) = generate_rsa2048_der_cert().expect("wrapper");
    let (_issued_pem, issued_der) = generate_rsa2048_der_cert().expect("issued");

    let access = store.access_key(&ca_id).expect("access");
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
