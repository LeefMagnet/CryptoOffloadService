//! KeyStore 单元测试：验证导入时一次性解析、key_id 引用、临时密钥销毁。

use crypto_offload_server::cryptooffload::v1::{HashAlgorithm, KeyFormat, KeyKind, KeyLifetime, SignAlgorithm};
use crypto_offload_server::crypto_sign;
use crypto_offload_server::key_store::KeyStore;
use crypto_offload_server::test_support::{extract_public_pem, generate_rsa2048_pem};

#[test]
fn import_pem_once_then_sign_without_reparse() {
    let store = KeyStore::new();
    let (priv_pem, _) = generate_rsa2048_pem().expect("generate key");

    let meta = store
        .import_key(
            KeyKind::Private as i32,
            KeyLifetime::Permanent as i32,
            KeyFormat::Pem as i32,
            &priv_pem,
            "test",
            &[],
            KeyFormat::Unspecified as i32,
        )
        .expect("import");

    assert!(!meta.key_id.is_empty());
    assert_eq!(meta.algorithm, "RSA");
    assert!(meta.key_bits >= 2048);

    let access = store.access_key(&meta.key_id).expect("access");
    let out = crypto_sign::sign(
        access,
        b"payload",
        HashAlgorithm::HashSha256 as i32,
        SignAlgorithm::SignRsaPkcs1V15 as i32,
    )
    .expect("sign");
    assert!(!out.signature.is_empty());

    // 永久密钥仍可再次使用
    let access2 = store.access_key(&meta.key_id).expect("access again");
    crypto_sign::sign(
        access2,
        b"payload2",
        HashAlgorithm::HashSha256 as i32,
        SignAlgorithm::SignRsaPkcs1V15 as i32,
    )
    .expect("sign again");
}

#[test]
fn temporary_key_consumed_after_first_use() {
    let store = KeyStore::new();
    let (priv_pem, _) = generate_rsa2048_pem().expect("generate key");

    let meta = store
        .import_key(
            KeyKind::Private as i32,
            KeyLifetime::Temporary as i32,
            KeyFormat::Pem as i32,
            &priv_pem,
            "tmp",
            &[],
            KeyFormat::Unspecified as i32,
        )
        .expect("import");

    let access = store.access_key(&meta.key_id).expect("access");
    crypto_sign::sign(
        access,
        b"x",
        HashAlgorithm::HashSha256 as i32,
        SignAlgorithm::Unspecified as i32,
    )
    .expect("sign");

    assert!(store.get_metadata(&meta.key_id).is_err());
}

#[test]
fn sign_and_verify_roundtrip() {
    let store = KeyStore::new();
    let (priv_pem, _) = generate_rsa2048_pem().expect("generate key");
    let pub_pem = extract_public_pem(&priv_pem).expect("public pem");

    let priv_meta = store
        .import_key(
            KeyKind::Private as i32,
            KeyLifetime::Permanent as i32,
            KeyFormat::Pem as i32,
            &priv_pem,
            "priv",
            &[],
            KeyFormat::Unspecified as i32,
        )
        .expect("import priv");

    let pub_meta = store
        .import_key(
            KeyKind::Public as i32,
            KeyLifetime::Permanent as i32,
            KeyFormat::Pem as i32,
            &pub_pem,
            "pub",
            &[],
            KeyFormat::Unspecified as i32,
        )
        .expect("import pub");

    let data = b"verify-me";
    let sig = crypto_sign::sign(
        store.access_key(&priv_meta.key_id).expect("priv"),
        data,
        HashAlgorithm::HashSha256 as i32,
        SignAlgorithm::SignRsaPkcs1V15 as i32,
    )
    .expect("sign")
    .signature;

    let valid = crypto_sign::verify(
        store.access_key(&pub_meta.key_id).expect("pub"),
        data,
        &sig,
        HashAlgorithm::HashSha256 as i32,
        SignAlgorithm::SignRsaPkcs1V15 as i32,
    )
    .expect("verify");
    assert!(valid);
}

#[test]
fn hash_algorithms_sha384_sha512() {
    let store = KeyStore::new();
    let (priv_pem, _) = generate_rsa2048_pem().expect("generate key");
    let meta = store
        .import_key(
            KeyKind::Private as i32,
            KeyLifetime::Permanent as i32,
            KeyFormat::Pem as i32,
            &priv_pem,
            "",
            &[],
            KeyFormat::Unspecified as i32,
        )
        .expect("import");

    for hash in [HashAlgorithm::HashSha384, HashAlgorithm::HashSha512] {
        let out = crypto_sign::sign(
            store.access_key(&meta.key_id).expect("access"),
            b"data",
            hash as i32,
            SignAlgorithm::SignRsaPkcs1V15 as i32,
        )
        .expect("sign");
        assert!(!out.signature.is_empty());
    }
}

#[test]
fn delete_key_removes_from_store() {
    let store = KeyStore::new();
    let (priv_pem, _) = generate_rsa2048_pem().expect("generate key");
    let meta = store
        .import_key(
            KeyKind::Private as i32,
            KeyLifetime::Permanent as i32,
            KeyFormat::Pem as i32,
            &priv_pem,
            "",
            &[],
            KeyFormat::Unspecified as i32,
        )
        .expect("import");

    assert!(store.delete_key(&meta.key_id).expect("delete"));
    assert!(store.get_metadata(&meta.key_id).is_err());
}
