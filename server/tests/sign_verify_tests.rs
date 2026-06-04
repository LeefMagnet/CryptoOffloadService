//! 全算法签名/验签矩阵测试。

use crypto_offload_server::crypto_sign;
use crypto_offload_server::cryptooffload::v1::{
    HashAlgorithm, KeyFormat, KeyKind, KeyLifetime, SignAlgorithm,
};
use crypto_offload_server::key_store::KeyStore;
use crypto_offload_server::test_support::{
    extract_public_pem, generate_ec256_pem, generate_ed25519_pem, generate_rsa2048_pem,
    generate_sm2_pem,
};

struct KeyPair {
    priv_id: String,
    pub_id: String,
}

fn import_rsa(store: &KeyStore) -> KeyPair {
    let (priv_pem, _) = generate_rsa2048_pem().expect("rsa");
    let pub_pem = extract_public_pem(&priv_pem).expect("pub");
    import_pair(store, &priv_pem, &pub_pem, &[], KeyFormat::Unspecified)
}

fn import_ec256(store: &KeyStore) -> KeyPair {
    let priv_pem = generate_ec256_pem().expect("ec256");
    let pub_pem = extract_public_pem(&priv_pem).expect("pub");
    import_pair(store, &priv_pem, &pub_pem, &[], KeyFormat::Unspecified)
}

fn import_sm2(store: &KeyStore) -> Option<KeyPair> {
    let (priv_pem, cert_pem) = generate_sm2_pem().ok()?;
    let pub_pem = extract_public_pem(&priv_pem).ok()?;
    Some(import_pair(
        store,
        &priv_pem,
        &pub_pem,
        &cert_pem,
        KeyFormat::Pem,
    ))
}

fn import_ed25519(store: &KeyStore) -> KeyPair {
    let priv_pem = generate_ed25519_pem().expect("ed25519");
    let pub_pem = extract_public_pem(&priv_pem).expect("pub");
    import_pair(store, &priv_pem, &pub_pem, &[], KeyFormat::Unspecified)
}

fn import_pair(
    store: &KeyStore,
    priv_pem: &[u8],
    pub_pem: &[u8],
    cert: &[u8],
    cert_fmt: KeyFormat,
) -> KeyPair {
    let priv_meta = store
        .import_key(
            KeyKind::Private as i32,
            KeyLifetime::Permanent as i32,
            KeyFormat::Pem as i32,
            priv_pem,
            "priv",
            cert,
            cert_fmt as i32,
        )
        .expect("import priv");
    let pub_meta = store
        .import_key(
            KeyKind::Public as i32,
            KeyLifetime::Permanent as i32,
            KeyFormat::Pem as i32,
            pub_pem,
            "pub",
            &[],
            KeyFormat::Unspecified as i32,
        )
        .expect("import pub");
    KeyPair {
        priv_id: priv_meta.key_id,
        pub_id: pub_meta.key_id,
    }
}

fn roundtrip(store: &KeyStore, keys: &KeyPair, data: &[u8], hash: i32, sign_alg: i32) {
    let sig = crypto_sign::sign(
        store.access_key(&keys.priv_id).expect("priv"),
        data,
        hash,
        sign_alg,
    )
    .expect("sign")
    .signature;

    let valid = crypto_sign::verify(
        store.access_key(&keys.pub_id).expect("pub"),
        data,
        &sig,
        hash,
        sign_alg,
    )
    .expect("verify");
    assert!(
        valid,
        "verify should pass for sign_alg={sign_alg} hash={hash}"
    );

    let mut bad = sig.clone();
    if let Some(b) = bad.last_mut() {
        *b ^= 0xFF;
    }
    let invalid = crypto_sign::verify(
        store.access_key(&keys.pub_id).expect("pub"),
        data,
        &bad,
        hash,
        sign_alg,
    )
    .expect("verify bad sig");
    assert!(!invalid, "tampered signature must fail");
}

#[test]
fn rsa_pkcs1_v15_sha256_roundtrip() {
    let store = KeyStore::new();
    let keys = import_rsa(&store);
    roundtrip(
        &store,
        &keys,
        b"rsa-sha256",
        HashAlgorithm::HashSha256 as i32,
        SignAlgorithm::SignRsaPkcs1V15 as i32,
    );
}

#[test]
fn rsa_pkcs1_v15_sha384_sha512_verify_roundtrip() {
    let store = KeyStore::new();
    let keys = import_rsa(&store);
    for hash in [HashAlgorithm::HashSha384, HashAlgorithm::HashSha512] {
        roundtrip(
            &store,
            &keys,
            b"rsa-multi-hash",
            hash as i32,
            SignAlgorithm::SignRsaPkcs1V15 as i32,
        );
    }
}

#[test]
fn rsa_pkcs1_v15_sha1_roundtrip() {
    let store = KeyStore::new();
    let keys = import_rsa(&store);
    roundtrip(
        &store,
        &keys,
        b"rsa-sha1",
        HashAlgorithm::HashSha1 as i32,
        SignAlgorithm::SignRsaPkcs1V15 as i32,
    );
}

#[test]
fn rsa_pss_sha256_roundtrip() {
    let store = KeyStore::new();
    let keys = import_rsa(&store);
    roundtrip(
        &store,
        &keys,
        b"rsa-pss",
        HashAlgorithm::HashSha256 as i32,
        SignAlgorithm::SignRsaPss as i32,
    );
}

#[test]
fn ecdsa_p256_sha256_roundtrip() {
    let store = KeyStore::new();
    let keys = import_ec256(&store);
    roundtrip(
        &store,
        &keys,
        b"ecdsa-p256",
        HashAlgorithm::HashSha256 as i32,
        SignAlgorithm::SignEcdsa as i32,
    );
}

#[test]
fn ecdsa_rejects_ed25519_sign_algorithm() {
    let store = KeyStore::new();
    let keys = import_ec256(&store);
    let err = crypto_sign::sign(
        store.access_key(&keys.priv_id).expect("priv"),
        b"x",
        HashAlgorithm::HashSha256 as i32,
        SignAlgorithm::SignEd25519 as i32,
    );
    assert!(err.is_err());
}

#[test]
fn sm2_roundtrip() {
    let store = KeyStore::new();
    let Some(keys) = import_sm2(&store) else {
        eprintln!("skip sm2_roundtrip: OpenSSL SM2 unavailable");
        return;
    };
    roundtrip(
        &store,
        &keys,
        b"sm2-data",
        HashAlgorithm::Unspecified as i32,
        SignAlgorithm::SignSm2 as i32,
    );
}

#[test]
fn sm2_rejects_non_sm3_hash() {
    let store = KeyStore::new();
    let Some(keys) = import_sm2(&store) else {
        return;
    };
    let err = crypto_sign::sign(
        store.access_key(&keys.priv_id).expect("priv"),
        b"x",
        HashAlgorithm::HashSha256 as i32,
        SignAlgorithm::SignSm2 as i32,
    );
    assert!(err.is_err());
}

/// SM2 sign/verify 已知向量测试（来自 OpenSSL 3.5.6 test/recipes/30-test_evp_data/evppkey_sm2.txt）
#[test]
fn sm2_known_vector_verify() {
    use crypto_offload_server::crypto_sm2::{sm2_verify, sm2_sign};
    use crypto_offload_server::pkey_util;
    use openssl::pkey::PKey;

    // 来自 evppkey_sm2.txt "SM2_key1" 的私钥 (PKCS8 PEM)
    let priv_pem = b"-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg0JFWczAXva2An9m7\n\
2MaT9gIwWTFptvlKrxyO4TjMmbWhRANCAAQ5OirZ4n5DrKqrhaGdO4VZHhRAYVcX\n\
Wt3Te/d/8Mr57Tf886i09VwDhSMmH8pmNq/mp6+ioUgqYG9cs6GLLioe\n\
-----END PRIVATE KEY-----\n";

    let pkey = PKey::private_key_from_pem(priv_pem).expect("parse SM2_key1");
    assert!(
        pkey_util::is_sm2(&pkey),
        "SM2_key1 must be recognized as SM2"
    );

    // 已知向量: D7AD397F6FFA5D4F7F11E7217F241607DC30618C236D2C09C1B9EA8FDADEE2E8
    let data = [
        0xD7, 0xAD, 0x39, 0x7F, 0x6F, 0xFA, 0x5D, 0x4F, 0x7F, 0x11, 0xE7, 0x21,
        0x7F, 0x24, 0x16, 0x07, 0xDC, 0x30, 0x61, 0x8C, 0x23, 0x6D, 0x2C, 0x09,
        0xC1, 0xB9, 0xEA, 0x8F, 0xDA, 0xDE, 0xE2, 0xE8,
    ];

    let sig = sm2_sign(&pkey, &data).expect("sm2_sign with known key");
    assert!(!sig.is_empty(), "signature must not be empty");

    // 验签（使用同一个密钥的 public key）
    let pub_der = pkey.public_key_to_der().expect("pub der");
    let pubkey = PKey::public_key_from_der(&pub_der).expect("pubkey");
    let valid = sm2_verify(&pubkey, &data, &sig).expect("verify");
    assert!(valid, "known SM2_key1 sign-verify roundtrip must succeed");

    // 负向：改一个字节应该验签失败
    let mut tampered = sig.clone();
    if let Some(b) = tampered.last_mut() {
        *b ^= 1;
    }
    let invalid = sm2_verify(&pubkey, &data, &tampered).expect("verify tampered");
    assert!(!invalid, "tampered signature must fail verification");
}

/// 用 OpenSSL test/certs/sm2.key 做签名/验签 roundtrip
#[test]
fn sm2_testdata_key_sign_verify_roundtrip() {
    use crypto_offload_server::crypto_sm2::{sm2_sign, sm2_verify};
    use crypto_offload_server::pkey_util;
    use openssl::pkey::PKey;

    let priv_pem = include_bytes!("../testdata/sm2/sm2.key");
    let pkey = match PKey::private_key_from_pem(priv_pem) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("skip sm2_testdata_key: {e}");
            return;
        }
    };
    assert!(
        pkey_util::is_sm2(&pkey),
        "sm2.key must be recognized as SM2"
    );

    let data = b"OpenSSL SM2 testdata key signature test";
    let sig = sm2_sign(&pkey, data).expect("sm2_sign");
    assert!(!sig.is_empty());

    let pub_der = pkey.public_key_to_der().expect("pub der");
    let pubkey = PKey::public_key_from_der(&pub_der).expect("pubkey");
    let valid = sm2_verify(&pubkey, data, &sig).expect("verify");
    assert!(valid, "SM2 testdata key roundtrip must succeed");
}

#[test]
fn ed25519_roundtrip() {
    let store = KeyStore::new();
    let keys = import_ed25519(&store);
    roundtrip(
        &store,
        &keys,
        b"ed25519-data",
        HashAlgorithm::Unspecified as i32,
        SignAlgorithm::SignEd25519 as i32,
    );
}

#[test]
fn ed25519_rejects_ecdsa_sign_algorithm() {
    let store = KeyStore::new();
    let keys = import_ed25519(&store);
    let err = crypto_sign::sign(
        store.access_key(&keys.priv_id).expect("priv"),
        b"x",
        HashAlgorithm::Unspecified as i32,
        SignAlgorithm::SignEcdsa as i32,
    );
    assert!(err.is_err());
}

#[test]
fn rsa_inferred_algorithm_defaults_pkcs1_v15() {
    let store = KeyStore::new();
    let keys = import_rsa(&store);
    let out = crypto_sign::sign(
        store.access_key(&keys.priv_id).expect("priv"),
        b"inferred",
        HashAlgorithm::HashSha256 as i32,
        SignAlgorithm::Unspecified as i32,
    )
    .expect("sign");
    assert_eq!(out.sign_algorithm, SignAlgorithm::SignRsaPkcs1V15 as i32);
}
