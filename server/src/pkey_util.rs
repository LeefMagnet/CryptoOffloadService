//! 密钥类型推断（OpenSSL 3.x 优先 `EVP_PKEY_get0_type_name`，与 PkiSdk 一致）。

use openssl::pkey::{HasPublic, Id, PKey, PKeyRef, Private, Public};

use crate::crypto_sm2;

/// 逻辑密钥族（用于算法推断与元数据）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkeyFamily {
    Rsa,
    Ec,
    Sm2,
    Ed25519,
    Unknown,
}

pub fn pkey_family_ref(key: &PKeyRef<impl HasPublic>) -> PkeyFamily {
    if crypto_sm2::is_sm2_pkey_ref(key) {
        return PkeyFamily::Sm2;
    }
    match key.id() {
        Id::RSA => PkeyFamily::Rsa,
        Id::EC => PkeyFamily::Ec,
        Id::SM2 => PkeyFamily::Sm2,
        Id::ED25519 => PkeyFamily::Ed25519,
        _ => match crypto_sm2::pkey_type_name_ref(key).as_deref() {
            Some("RSA") => PkeyFamily::Rsa,
            Some("EC") => PkeyFamily::Ec,
            Some("ED25519") => PkeyFamily::Ed25519,
            _ => PkeyFamily::Unknown,
        },
    }
}

pub fn pkey_family<T: HasPublic>(key: &PKey<T>) -> PkeyFamily {
    pkey_family_ref(key)
}

pub fn algorithm_label<T: HasPublic>(key: &PKey<T>) -> String {
    algorithm_label_ref(key)
}

pub fn algorithm_label_ref(key: &PKeyRef<impl HasPublic>) -> String {
    if crypto_sm2::is_sm2_pkey_ref(key) {
        return "SM2".to_string();
    }
    if let Some(name) = crypto_sm2::pkey_type_name_ref(key) {
        if !name.is_empty() {
            return name;
        }
    }
    match key.id() {
        Id::RSA => "RSA".to_string(),
        Id::EC => "EC".to_string(),
        Id::SM2 => "SM2".to_string(),
        Id::ED25519 => "Ed25519".to_string(),
        other => format!("{other:?}"),
    }
}

pub fn is_sm2_key(key: &PKeyRef<impl HasPublic>) -> bool {
    crypto_sm2::is_sm2_pkey_ref(key)
}

pub fn validate_sign_algorithm(
    family: PkeyFamily,
    alg: crate::pb::SignAlgorithm,
) -> anyhow::Result<()> {
    use crate::pb::SignAlgorithm::*;
    match (family, alg) {
        (PkeyFamily::Rsa, SignRsaPkcs1V15) | (PkeyFamily::Rsa, SignRsaPss) => Ok(()),
        (PkeyFamily::Ec, SignEcdsa) => Ok(()),
        (PkeyFamily::Sm2, SignSm2) => Ok(()),
        (PkeyFamily::Ed25519, SignEd25519) => Ok(()),
        (PkeyFamily::Rsa, _) => {
            anyhow::bail!("RSA key requires SIGN_RSA_PKCS1_V15 or SIGN_RSA_PSS")
        }
        (PkeyFamily::Ec, _) => anyhow::bail!("EC key requires SIGN_ECDSA"),
        (PkeyFamily::Sm2, _) => anyhow::bail!("SM2 key requires SIGN_SM2"),
        (PkeyFamily::Ed25519, _) => anyhow::bail!("Ed25519 key requires SIGN_ED25519"),
        (PkeyFamily::Unknown, _) => anyhow::bail!("unsupported key type for signing"),
    }
}

pub fn infer_sign_algorithm(
    family: PkeyFamily,
    requested: crate::pb::SignAlgorithm,
) -> anyhow::Result<crate::pb::SignAlgorithm> {
    use crate::pb::SignAlgorithm::*;
    if requested != Unspecified {
        validate_sign_algorithm(family, requested)?;
        return Ok(requested);
    }
    Ok(match family {
        PkeyFamily::Rsa => SignRsaPkcs1V15,
        PkeyFamily::Ec => SignEcdsa,
        PkeyFamily::Ed25519 => SignEd25519,
        PkeyFamily::Sm2 => SignSm2,
        PkeyFamily::Unknown => anyhow::bail!("unsupported key type for signing"),
    })
}

pub fn family_from_private(key: &PKey<Private>) -> PkeyFamily {
    pkey_family(key)
}

pub fn family_from_public(key: &PKey<Public>) -> PkeyFamily {
    pkey_family(key)
}
