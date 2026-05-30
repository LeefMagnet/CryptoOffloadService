//! 全算法签名/验签矩阵测试。

use crypto_offload_server::cryptooffload::v1::{HashAlgorithm, KeyFormat, KeyKind, KeyLifetime, SignAlgorithm};
use crypto_offload_server::crypto_sign;
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

fn roundtrip(
    store: &KeyStore,
    keys: &KeyPair,
    data: &[u8],
    hash: i32,
    sign_alg: i32,
) {
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
    assert!(valid, "verify should pass for sign_alg={sign_alg} hash={hash}");

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
