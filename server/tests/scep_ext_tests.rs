//! ScepExtService 单元测试。

use crypto_offload_server::crypto_scep_ext;
use crypto_offload_server::openssl_init;

#[test]
fn scep_ext_encode_decode_cert_alias() {
    openssl_init::init();
    for (ty, value) in [(1, "device-alias"), (2, "device-cn.example.com")] {
        let der = crypto_scep_ext::encode_cert_alias_content(ty, value).expect("encode");
        let (got_ty, alias_or_cn, serial) =
            crypto_scep_ext::decode_cert_alias_content(&der).expect("decode");
        assert_eq!(got_ty, ty);
        assert_eq!(alias_or_cn, value);
        assert!(serial.is_empty());
    }
}

#[test]
fn scep_ext_encode_decode_serial_number() {
    openssl_init::init();
    let der = crypto_scep_ext::encode_cert_alias_content(3, "1A2B3C").expect("encode");
    let (ty, alias, serial) = crypto_scep_ext::decode_cert_alias_content(&der).expect("decode");
    assert_eq!(ty, 3);
    assert!(alias.is_empty());
    assert_eq!(serial.to_ascii_uppercase(), "1A2B3C");
}

#[test]
fn scep_ext_decode_malformed_der_returns_error_not_panic() {
    openssl_init::init();
    let malformed_cases = [
        vec![0x30, 0x82, 0xFF, 0xFF, 0x02, 0x01, 0x01],
        vec![0x30, 0x05, 0x02, 0x04, 0x01, 0x02],
        vec![0xA0, 0x82, 0xFF, 0xFF, 0x0C, 0x01, b'A'],
    ];

    for der in malformed_cases {
        let outcome = std::panic::catch_unwind(|| crypto_scep_ext::decode_cert_alias_content(&der));
        assert!(outcome.is_ok(), "malformed DER should not panic");
        assert!(outcome.expect("decode run").is_err(), "malformed DER should be rejected");
    }
}

#[test]
fn scep_ext_parse_signed_attributes_from_certrep() {
    openssl_init::init();
    use crypto_offload_server::cryptooffload::v1::{KeyFormat, KeyKind, KeyLifetime};
    use crypto_offload_server::crypto_scep;
    use crypto_offload_server::key_store::KeyStore;
    use crypto_offload_server::test_support::generate_rsa2048_der_cert;

    let store = KeyStore::new();
    let (ca_pem, ca_der) = generate_rsa2048_der_cert().expect("ca");
    let meta = store
        .import_key(
            KeyKind::Private as i32,
            KeyLifetime::Permanent as i32,
            KeyFormat::Pem as i32,
            &ca_pem,
            "ca",
            &ca_der,
            KeyFormat::Der as i32,
        )
        .expect("import");
    let access = store.access_key(&meta.key_id).expect("access");
    let certrep = crypto_scep::build_failure_certrep(
        access,
        "tx-ext-attr",
        &[1, 2, 3, 4],
        &[],
        2,
        "policy deny",
    )
    .expect("certrep");

    let attrs = crypto_scep_ext::parse_signed_attributes(&certrep).expect("parse attrs");
    assert_eq!(attrs.transaction_id, "tx-ext-attr");
    assert_eq!(attrs.message_type, 3); // CertRep
    assert_eq!(attrs.pki_status, 2); // FAILURE proto enum
    assert_eq!(attrs.fail_info, 3); // badRequest proto enum
    assert_eq!(attrs.fail_info_text, "policy deny");
    assert_eq!(attrs.recipient_nonce, vec![1, 2, 3, 4]);
}

#[test]
fn scep_ext_parse_enroll_pkio() {
    openssl_init::init();
    use crypto_offload_server::cryptooffload::v1::{KeyFormat, KeyKind, KeyLifetime};
    use crypto_offload_server::crypto_scep;
    use crypto_offload_server::key_store::KeyStore;
    use crypto_offload_server::test_support::{generate_rsa2048_der_cert, generate_scep_pkio};
    use openssl::x509::X509;

    let store = KeyStore::new();
    let (ca_pem, ca_der) = generate_rsa2048_der_cert().expect("ca");
    let ca_cert = X509::from_der(&ca_der).expect("cert");
    let (pkio, expected_csr, expected_wrapper) = generate_scep_pkio(&ca_cert).expect("pkio");

    let meta = store
        .import_key(
            KeyKind::Private as i32,
            KeyLifetime::Permanent as i32,
            KeyFormat::Pem as i32,
            &ca_pem,
            "ca",
            &ca_der,
            KeyFormat::Der as i32,
        )
        .expect("import");
    let access = store.access_key(&meta.key_id).expect("access");

    let resp = crypto_scep_ext::parse_enroll_pkio(&pkio, access).expect("parse enroll");
    assert_eq!(resp.csr_der, expected_csr);
    assert_eq!(resp.wrapper_cert_der, expected_wrapper);
    assert!(resp.attributes.is_some());

    // 与 ScepService.ParseRequest 结果一致
    let access2 = store.access_key(&meta.key_id).expect("access");
    let (csr2, wrapper2) = crypto_scep::parse_request(&pkio, access2).expect("parse request");
    assert_eq!(resp.csr_der, csr2);
    assert_eq!(resp.wrapper_cert_der, wrapper2);
}

#[test]
fn scep_ext_parse_getcert_pkio() {
    openssl_init::init();
    use crypto_offload_server::cryptooffload::v1::{KeyFormat, KeyKind, KeyLifetime};
    use crypto_offload_server::key_store::KeyStore;
    use crypto_offload_server::test_support::{generate_getcert_pkio, generate_rsa2048_der_cert};
    use openssl::x509::X509;

    let store = KeyStore::new();
    let (ca_pem, ca_der) = generate_rsa2048_der_cert().expect("ca");
    let ca_cert = X509::from_der(&ca_der).expect("cert");
    let (pkio, inner, _wrapper) =
        generate_getcert_pkio(&ca_cert, "iot-device-001").expect("pkio");
    assert_eq!(inner, crypto_scep_ext::encode_cert_alias_content(1, "iot-device-001").unwrap());

    let meta = store
        .import_key(
            KeyKind::Private as i32,
            KeyLifetime::Permanent as i32,
            KeyFormat::Pem as i32,
            &ca_pem,
            "ca",
            &ca_der,
            KeyFormat::Der as i32,
        )
        .expect("import");
    let access = store.access_key(&meta.key_id).expect("access");
    let resp = crypto_scep_ext::parse_getcert_pkio(&pkio, access).expect("parse getcert");
    assert_eq!(resp.content_type, 1);
    assert_eq!(resp.alias_or_cn, "iot-device-001");
    assert!(!resp.wrapper_cert_der.is_empty());
}
