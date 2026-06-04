//! SCEP CertRep 与 PKIO 单元测试。
//!
//! OpenSSL 3.x 下 DES/3DES 在 **legacy provider** 中；Debian bookworm 等需安装
//! `openssl-provider-legacy`，否则部分 Envelop 算法测试会失败。

use crypto_offload_server::crypto_scep;
use crypto_offload_server::cryptooffload::v1::{KeyFormat, KeyKind, KeyLifetime};
use crypto_offload_server::key_store::KeyStore;
use crypto_offload_server::openssl_init;
use crypto_offload_server::test_support::{
    generate_rsa2048_der_cert, generate_scep_pkio, generate_scep_pkio_ed25519_password,
    generate_scep_pkio_password, generate_scep_pkio_password_rsa_wrapper,
};
use openssl::x509::X509;

/// RFC 8894 推荐
const ENVELOPE_AES128_CBC: i32 = 1;
/// step-ca `encryptionAlgorithmIdentifier: 2`
const ENVELOPE_AES256_CBC: i32 = 2;
const ENVELOPE_AES128_GCM: i32 = 3;
const ENVELOPE_AES256_GCM: i32 = 4;
/// SCEP GetCACaps DES3
const ENVELOPE_DES3_CBC: i32 = 5;

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

fn build_success_certrep_with_cipher(
    store: &KeyStore,
    ca_id: &str,
    tx: &str,
    nonce: &[u8],
    issued_der: &[u8],
    wrapper_der: &[u8],
    envelope_cipher: i32,
    challenge_password: Option<&str>,
) -> Vec<u8> {
    let access = store.access_key(ca_id).expect("access ca");
    crypto_scep::build_success_certrep(
        access,
        tx,
        nonce,
        &[],
        issued_der,
        wrapper_der,
        envelope_cipher,
        challenge_password,
    )
    .unwrap_or_else(|e| panic!("build SUCCESS CertRep cipher={envelope_cipher}: {e}"))
}

fn build_gm_success_certrep_with_cipher(
    store: &KeyStore,
    ca_id: &str,
    tx: &str,
    nonce: &[u8],
    sign_der: &[u8],
    enc_der: &[u8],
    skf: &[u8],
    wrapper_der: &[u8],
    envelope_cipher: i32,
    challenge_password: Option<&str>,
) -> Vec<u8> {
    let access = store.access_key(ca_id).expect("access ca");
    crypto_scep::build_gm_success_certrep(
        access,
        tx,
        nonce,
        &[],
        sign_der,
        enc_der,
        skf,
        wrapper_der,
        envelope_cipher,
        challenge_password,
    )
    .unwrap_or_else(|e| panic!("build GM SUCCESS CertRep cipher={envelope_cipher}: {e}"))
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
        crypto_scep::parse_request(&pkio_der, access, None).expect("parse 3DES SCEP PKIO");

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
        crypto_scep::parse_request(&pkio_der, access, None).expect("parse PKIO");
    assert!(!csr_der.is_empty());

    let access = store.access_key(&ca_id).expect("access ca again");
    let certrep = crypto_scep::build_success_certrep(
        access,
        "tx-roundtrip-3des",
        &[0xAA, 0xBB, 0xCC, 0xDD],
        &[],
        &issued_der,
        &wrapper_cert_der,
        ENVELOPE_DES3_CBC,
        None,
    )
    .expect("build SUCCESS CertRep with 3DES Envelop");
    assert!(!certrep.is_empty());
}

#[test]
fn scep_build_pending_certrep() {
    init_scep_test_openssl();

    let store = KeyStore::new();
    let (ca_id, _ca_der) = import_ca(&store, "scep-ca-pending");

    let access = store.access_key(&ca_id).expect("access");
    let certrep =
        crypto_scep::build_pending_certrep(access, "tx-pending-789", &[5u8, 6, 7, 8], &[])
            .expect("build pending certrep");
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
fn scep_build_success_certrep_default_unspecified_to_aes128() {
    init_scep_test_openssl();
    let store = KeyStore::new();
    let (ca_id, _) = import_ca(&store, "scep-ca-des");
    let (_wrapper_pem, wrapper_der) = generate_rsa2048_der_cert().expect("wrapper");
    let (_issued_pem, issued_der) = generate_rsa2048_der_cert().expect("issued");
    let certrep = build_success_certrep_with_cipher(
        &store,
        &ca_id,
        "tx-default-unspecified",
        &[0x01],
        &issued_der,
        &wrapper_der,
        ENVELOPE_AES128_CBC,
        None,
    );
    assert!(!certrep.is_empty());
}

#[test]
fn scep_build_success_certrep_aes128_cbc() {
    init_scep_test_openssl();
    let store = KeyStore::new();
    let (ca_id, _) = import_ca(&store, "scep-ca-aes128");
    let (_wrapper_pem, wrapper_der) = generate_rsa2048_der_cert().expect("wrapper");
    let (_issued_pem, issued_der) = generate_rsa2048_der_cert().expect("issued");
    let certrep = build_success_certrep_with_cipher(
        &store,
        &ca_id,
        "tx-aes128-cbc",
        &[0x02],
        &issued_der,
        &wrapper_der,
        ENVELOPE_AES128_CBC,
        None,
    );
    assert!(!certrep.is_empty());
}

#[test]
fn scep_build_success_certrep_aes256_cbc() {
    init_scep_test_openssl();
    let store = KeyStore::new();
    let (ca_id, _) = import_ca(&store, "scep-ca-aes256");
    let (_wrapper_pem, wrapper_der) = generate_rsa2048_der_cert().expect("wrapper");
    let (_issued_pem, issued_der) = generate_rsa2048_der_cert().expect("issued");
    let certrep = build_success_certrep_with_cipher(
        &store,
        &ca_id,
        "tx-aes256-cbc",
        &[0x03],
        &issued_der,
        &wrapper_der,
        ENVELOPE_AES256_CBC,
        None,
    );
    assert!(!certrep.is_empty());
}

#[test]
fn scep_build_success_certrep() {
    init_scep_test_openssl();

    let store = KeyStore::new();
    let (ca_id, _ca_der) = import_ca(&store, "scep-ca-success");
    let (_wrapper_pem, wrapper_der) = generate_rsa2048_der_cert().expect("wrapper");
    let (_issued_pem, issued_der) = generate_rsa2048_der_cert().expect("issued");

    let certrep = build_success_certrep_with_cipher(
        &store,
        &ca_id,
        "tx-456",
        &[9u8, 8, 7, 6],
        &issued_der,
        &wrapper_der,
        ENVELOPE_AES128_CBC,
        None,
    );
    assert!(!certrep.is_empty());
}

#[test]
fn scep_build_success_certrep_extended_envelope_ciphers() {
    init_scep_test_openssl();

    let store = KeyStore::new();
    let (ca_id, _ca_der) = import_ca(&store, "scep-ca-ext-ciphers");
    let (_wrapper_pem, wrapper_der) = generate_rsa2048_der_cert().expect("wrapper");
    let (_issued_pem, issued_der) = generate_rsa2048_der_cert().expect("issued");

    for cipher in [ENVELOPE_AES128_GCM, ENVELOPE_AES256_GCM, ENVELOPE_DES3_CBC] {
        let certrep = build_success_certrep_with_cipher(
            &store,
            &ca_id,
            &format!("tx-ext-{cipher}"),
            &[cipher as u8],
            &issued_der,
            &wrapper_der,
            cipher,
            None,
        );
        assert!(!certrep.is_empty(), "cipher {cipher}");
    }
}

#[test]
fn scep_build_gm_inner_signed_data_dual_cert_and_skf() {
    init_scep_test_openssl();

    use crypto_offload_server::scep_certrep::build_gm_inner_signed_data;

    let (_sign_pem, sign_der) = generate_rsa2048_der_cert().expect("sign");
    let (_enc_pem, enc_der) = generate_rsa2048_der_cert().expect("enc");
    let sign_cert = X509::from_der(&sign_der).expect("sign cert");
    let enc_cert = X509::from_der(&enc_der).expect("enc cert");
    let skf = b"BASE64SKFKEYPAIRDATA==";

    let inner = build_gm_inner_signed_data(&sign_cert, &enc_cert, skf).expect("inner");
    assert!(
        inner.windows(skf.len()).any(|w| w == skf),
        "inner SignedData must embed SKF Base64 bytes in eContent"
    );
    assert!(inner.len() > sign_der.len() + enc_der.len());
}

#[test]
fn scep_build_gm_success_certrep_default_unspecified_to_aes128() {
    init_scep_test_openssl();
    let store = KeyStore::new();
    let (ca_id, _) = import_ca(&store, "scep-ca-gm-des");
    let (_sign_pem, sign_der) = generate_rsa2048_der_cert().expect("sign");
    let (_enc_pem, enc_der) = generate_rsa2048_der_cert().expect("enc");
    let (_wrapper_pem, wrapper_der) = generate_rsa2048_der_cert().expect("wrapper");
    let skf = b"dGVzdC1za2YtYmFzZTY0";
    let certrep = build_gm_success_certrep_with_cipher(
        &store,
        &ca_id,
        "tx-gm-default-unspecified",
        &[0x01],
        &sign_der,
        &enc_der,
        skf,
        &wrapper_der,
        ENVELOPE_AES128_CBC,
        None,
    );
    assert!(!certrep.is_empty());
}

#[test]
fn scep_build_gm_success_certrep_aes128_cbc() {
    init_scep_test_openssl();
    let store = KeyStore::new();
    let (ca_id, _) = import_ca(&store, "scep-ca-gm-aes128");
    let (_sign_pem, sign_der) = generate_rsa2048_der_cert().expect("sign");
    let (_enc_pem, enc_der) = generate_rsa2048_der_cert().expect("enc");
    let (_wrapper_pem, wrapper_der) = generate_rsa2048_der_cert().expect("wrapper");
    let skf = b"dGVzdC1za2YtYmFzZTY0";
    let certrep = build_gm_success_certrep_with_cipher(
        &store,
        &ca_id,
        "tx-gm-aes128",
        &[0x02],
        &sign_der,
        &enc_der,
        skf,
        &wrapper_der,
        ENVELOPE_AES128_CBC,
        None,
    );
    assert!(!certrep.is_empty());
}

#[test]
fn scep_build_gm_success_certrep_aes256_cbc() {
    init_scep_test_openssl();
    let store = KeyStore::new();
    let (ca_id, _) = import_ca(&store, "scep-ca-gm-aes256");
    let (_sign_pem, sign_der) = generate_rsa2048_der_cert().expect("sign");
    let (_enc_pem, enc_der) = generate_rsa2048_der_cert().expect("enc");
    let (_wrapper_pem, wrapper_der) = generate_rsa2048_der_cert().expect("wrapper");
    let skf = b"dGVzdC1za2YtYmFzZTY0";
    let certrep = build_gm_success_certrep_with_cipher(
        &store,
        &ca_id,
        "tx-gm-aes256",
        &[0x03],
        &sign_der,
        &enc_der,
        skf,
        &wrapper_der,
        ENVELOPE_AES256_CBC,
        None,
    );
    assert!(!certrep.is_empty());
}

#[test]
fn scep_build_gm_success_certrep_des3_envelope() {
    init_scep_test_openssl();

    let store = KeyStore::new();
    let (ca_id, _ca_der) = import_ca(&store, "scep-ca-gm-3des");
    let (_sign_pem, sign_der) = generate_rsa2048_der_cert().expect("sign");
    let (_enc_pem, enc_der) = generate_rsa2048_der_cert().expect("enc");
    let (_wrapper_pem, wrapper_der) = generate_rsa2048_der_cert().expect("wrapper");
    let skf = b"dGVzdC1za2YtYmFzZTY0";
    let certrep = build_gm_success_certrep_with_cipher(
        &store,
        &ca_id,
        "tx-gm-3des",
        &[0x04],
        &sign_der,
        &enc_der,
        skf,
        &wrapper_der,
        ENVELOPE_DES3_CBC,
        None,
    );
    assert!(!certrep.is_empty());
}

#[test]
fn scep_password_envelope_roundtrip() {
    init_scep_test_openssl();
    let plain = b"pkcs10-csr-placeholder-bytes";
    let password = "device-shared-secret-32chars!!";
    let env = crypto_offload_server::scep_password_envelope::encrypt_envelope_password(
        plain,
        password,
        openssl::symm::Cipher::aes_128_cbc(),
    )
    .expect("encrypt password envelope");
    let out =
        crypto_offload_server::scep_password_envelope::decrypt_envelope_password(&env, password)
            .expect("decrypt password envelope");
    assert_eq!(out, plain);
}

#[test]
fn scep_parse_request_password_pkio() {
    init_scep_test_openssl();
    let store = KeyStore::new();
    let (ca_id, _ca_der) = import_ca(&store, "scep-ca-pw-parse");
    let password = "enroll-challenge-pw-001";
    let csr = b"mock-csr-der-for-password-envelope";
    let (pkio_der, expected_plain, expected_wrapper) =
        generate_scep_pkio_password(password, csr).expect("password PKIO fixture");
    let access = store.access_key(&ca_id).expect("access");
    let (plain, wrapper) =
        crypto_scep::parse_request(&pkio_der, access, Some(password)).expect("parse password PKIO");
    assert_eq!(plain, expected_plain);
    assert_eq!(wrapper, expected_wrapper);
}

#[test]
fn scep_parse_request_rsa_csr_uses_ca_not_challenge() {
    init_scep_test_openssl();
    let store = KeyStore::new();
    let (ca_id, ca_der) = import_ca(&store, "scep-ca-rsa-prio");
    let ca_cert = X509::from_der(&ca_der).expect("ca cert");
    let (pkio_der, expected_csr, expected_wrapper) =
        generate_scep_pkio(&ca_cert).expect("RSA envelope PKIO");

    let access = store.access_key(&ca_id).expect("access");
    let (csr, wrapper) = crypto_scep::parse_request(&pkio_der, access, Some("ignored-challenge"))
        .expect("CA KeyTrans decrypt must succeed without valid challenge");
    assert_eq!(csr, expected_csr);
    assert_eq!(wrapper, expected_wrapper);

    let enveloped = {
        let outer = openssl::pkcs7::Pkcs7::from_der(&pkio_der).expect("pkcs7");
        crypto_offload_server::scep_pkio::extract_signed_content(&outer).expect("envelope")
    };
    assert!(
        !crypto_offload_server::scep_password_envelope::enveloped_uses_password_recipient(
            &enveloped
        )
        .expect("pwri check"),
        "3DES KeyTrans enroll must not use PasswordRecipientInfo"
    );
}

#[test]
fn scep_parse_request_ed25519_csr_password_envelope() {
    init_scep_test_openssl();
    let store = KeyStore::new();
    let (ca_id, _) = import_ca(&store, "scep-ca-ed25519-pw");
    let password = "ed25519-enroll-challenge-pw";
    let (pkio_der, expected_csr, expected_wrapper) =
        generate_scep_pkio_ed25519_password(password).expect("ed25519 password PKIO");

    let access = store.access_key(&ca_id).expect("access");
    let (csr, wrapper) =
        crypto_scep::parse_request(&pkio_der, access, Some(password)).expect("parse ed25519 PKIO");
    assert_eq!(csr, expected_csr);
    assert_eq!(wrapper, expected_wrapper);

    let wrapper_cert = X509::from_der(&wrapper).expect("wrapper");
    assert!(
        wrapper_cert.public_key().expect("pk").rsa().is_ok(),
        "password-envelope fixture uses RSA wrapper for outer sign"
    );
    let req = openssl::x509::X509Req::from_der(&csr).expect("pkcs10");
    assert!(
        req.public_key()
            .expect("csr pubkey")
            .id()
            .eq(&openssl::pkey::Id::ED25519),
        "inner plaintext must be Ed25519 PKCS#10 CSR"
    );
}

#[test]
fn scep_parse_password_envelope_rsa_wrapper_prefers_challenge() {
    init_scep_test_openssl();
    let store = KeyStore::new();
    let (ca_id, _) = import_ca(&store, "scep-ca-pw-rsa-wrap");
    let password = "rsa-wrapper-challenge-pw-01";
    let csr = b"pkcs10-rsa-csr-placeholder";
    let (pkio_der, expected_plain, expected_wrapper) =
        generate_scep_pkio_password_rsa_wrapper(password, csr).expect("rsa wrapper password PKIO");

    let wrapper_cert = X509::from_der(&expected_wrapper).expect("wrapper");
    assert!(
        wrapper_cert.public_key().expect("pk").rsa().is_ok(),
        "wrapper must remain RSA even when decrypt uses challenge"
    );

    let access = store.access_key(&ca_id).expect("access");
    let (plain, wrapper) =
        crypto_scep::parse_request(&pkio_der, access, Some(password)).expect("challenge decrypt");
    assert_eq!(plain, expected_plain);
    assert_eq!(wrapper, expected_wrapper);

    let access2 = store.access_key(&ca_id).expect("access again");
    assert!(
        crypto_scep::parse_request(&pkio_der, access2, None).is_err(),
        "PasswordRecipientInfo must not fall back to CA RSA decrypt"
    );

    let access3 = store.access_key(&ca_id).expect("access wrong pw");
    assert!(
        crypto_scep::parse_request(&pkio_der, access3, Some("wrong-password")).is_err(),
        "wrong challenge must fail even with valid CA key"
    );
}

#[test]
fn scep_build_success_certrep_rsa_wrapper_with_challenge_uses_password_envelope() {
    init_scep_test_openssl();
    let store = KeyStore::new();
    let (ca_id, _) = import_ca(&store, "scep-ca-build-pw-rsa");
    let password = "certrep-challenge-with-rsa-wrap";
    let (_wrapper_pem, wrapper_der) = generate_rsa2048_der_cert().expect("wrapper");
    let (_issued_pem, issued_der) = generate_rsa2048_der_cert().expect("issued");
    let certrep = build_success_certrep_with_cipher(
        &store,
        &ca_id,
        "tx-pw-rsa-wrapper",
        &[0x55, 0x66],
        &issued_der,
        &wrapper_der,
        ENVELOPE_AES128_CBC,
        Some(password),
    );
    let outer = openssl::pkcs7::Pkcs7::from_der(&certrep).expect("certrep pkcs7");
    let enveloped_der =
        crypto_offload_server::scep_pkio::extract_signed_content(&outer).expect("inner envelope");
    assert!(
        crypto_offload_server::scep_password_envelope::enveloped_uses_password_recipient(
            &enveloped_der
        )
        .expect("pwri"),
        "non-empty challenge_password must use PasswordRecipientInfo, not RSA wrapper pubkey"
    );
    let plain = crypto_offload_server::scep_password_envelope::decrypt_envelope_password(
        &enveloped_der,
        password,
    )
    .expect("decrypt with challenge");
    assert!(!plain.is_empty());
}

#[test]
fn scep_build_success_certrep_password_envelope() {
    init_scep_test_openssl();
    let store = KeyStore::new();
    let (ca_id, _) = import_ca(&store, "scep-ca-pw-certrep");
    let password = "enroll-challenge-pw-002";
    let (_issued_pem, issued_der) = generate_rsa2048_der_cert().expect("issued");
    let certrep = build_success_certrep_with_cipher(
        &store,
        &ca_id,
        "tx-pw-certrep",
        &[0x11, 0x22, 0x33, 0x44],
        &issued_der,
        &[],
        ENVELOPE_AES128_CBC,
        Some(password),
    );
    assert!(!certrep.is_empty());
    let outer = openssl::pkcs7::Pkcs7::from_der(&certrep).expect("certrep pkcs7");
    let enveloped_der =
        crypto_offload_server::scep_pkio::extract_signed_content(&outer).expect("inner envelope");
    assert!(
        crypto_offload_server::scep_password_envelope::enveloped_uses_password_recipient(
            &enveloped_der
        )
        .expect("pwri")
    );
    let plain = crypto_offload_server::scep_password_envelope::decrypt_envelope_password(
        &enveloped_der,
        password,
    )
    .expect("decrypt certrep");
    assert!(!plain.is_empty());
}
