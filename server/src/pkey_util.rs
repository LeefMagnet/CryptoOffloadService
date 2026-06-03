//! `EVP_PKEY` 分类与签名策略（OpenSSL 3.x `EVP_PKEY_get0_type_name`，与 PkiSdk 一致）。

use std::ffi::CStr;

use anyhow::{bail, Result};
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, Id, PKeyRef};
use openssl_sys as ffi;

use crate::pb::{HashAlgorithm, SignAlgorithm};

/// 逻辑密钥族（导入后推断默认签名算法）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFamily {
    Rsa,
    Ec,
    Sm2,
    Ed25519,
    Unknown,
}

#[link(name = "crypto")]
extern "C" {
    fn EVP_PKEY_get0_type_name(pkey: *const ffi::EVP_PKEY) -> *const std::os::raw::c_char;
}

/// OpenSSL 3.x 密钥类型名（如 `"SM2"` / `"EC"` / `"RSA"`）。
pub fn openssl_type_name(key: &PKeyRef<impl HasPublic>) -> Option<String> {
    unsafe {
        let ptr = EVP_PKEY_get0_type_name(key.as_ptr());
        if ptr.is_null() {
            return None;
        }
        Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
    }
}

/// SM2 判定：优先 `Id::SM2` 与 type name，再回退 SM2 曲线（PKCS#8 导入后 `Id` 可能为 `EC`）。
pub fn is_sm2(key: &PKeyRef<impl HasPublic>) -> bool {
    if key.id() == Id::SM2 {
        return true;
    }
    if openssl_type_name(key).is_some_and(|n| n.eq_ignore_ascii_case("sm2")) {
        return true;
    }
    key.ec_key()
        .ok()
        .and_then(|ec| ec.group().curve_name())
        .is_some_and(|nid| nid == Nid::SM2)
}

pub fn family(key: &PKeyRef<impl HasPublic>) -> KeyFamily {
    if is_sm2(key) {
        return KeyFamily::Sm2;
    }
    match key.id() {
        Id::RSA => KeyFamily::Rsa,
        Id::EC => KeyFamily::Ec,
        Id::SM2 => KeyFamily::Sm2,
        Id::ED25519 => KeyFamily::Ed25519,
        _ => match openssl_type_name(key).as_deref() {
            Some("RSA") => KeyFamily::Rsa,
            Some("EC") => KeyFamily::Ec,
            Some("ED25519") => KeyFamily::Ed25519,
            _ => KeyFamily::Unknown,
        },
    }
}

/// ImportKey 元数据中的 `algorithm` 字段。
pub fn algorithm_name(key: &PKeyRef<impl HasPublic>) -> String {
    if is_sm2(key) {
        return "SM2".to_string();
    }
    if let Some(name) = openssl_type_name(key) {
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

pub fn validate_sign_algorithm(family: KeyFamily, alg: SignAlgorithm) -> Result<()> {
    use SignAlgorithm::*;
    match (family, alg) {
        (KeyFamily::Rsa, SignRsaPkcs1V15) | (KeyFamily::Rsa, SignRsaPss) => Ok(()),
        (KeyFamily::Ec, SignEcdsa) => Ok(()),
        (KeyFamily::Sm2, SignSm2) => Ok(()),
        (KeyFamily::Ed25519, SignEd25519) => Ok(()),
        (KeyFamily::Rsa, _) => bail!("RSA key requires SIGN_RSA_PKCS1_V15 or SIGN_RSA_PSS"),
        (KeyFamily::Ec, _) => bail!("EC key requires SIGN_ECDSA"),
        (KeyFamily::Sm2, _) => bail!("SM2 key requires SIGN_SM2"),
        (KeyFamily::Ed25519, _) => bail!("Ed25519 key requires SIGN_ED25519"),
        (KeyFamily::Unknown, _) => bail!("unsupported key type for signing"),
    }
}

/// 解析请求中的签名算法；未指定时按密钥族选择默认值。
pub fn resolve_sign_algorithm(
    family: KeyFamily,
    requested: SignAlgorithm,
) -> Result<SignAlgorithm> {
    use SignAlgorithm::*;
    if requested != Unspecified {
        validate_sign_algorithm(family, requested)?;
        return Ok(requested);
    }
    Ok(match family {
        KeyFamily::Rsa => SignRsaPkcs1V15,
        KeyFamily::Ec => SignEcdsa,
        KeyFamily::Ed25519 => SignEd25519,
        KeyFamily::Sm2 => SignSm2,
        KeyFamily::Unknown => bail!("unsupported key type for signing"),
    })
}

/// 按签名算法规范化 `hash_algorithm`（SM2→SM3，Ed25519 不使用外部摘要）。
pub fn resolve_hash_for_sign(hash: i32, sign_alg: SignAlgorithm) -> Result<i32> {
    if sign_alg == SignAlgorithm::SignEd25519 {
        let h = HashAlgorithm::try_from(hash).unwrap_or(HashAlgorithm::Unspecified);
        if h != HashAlgorithm::Unspecified {
            bail!("Ed25519 does not use hash_algorithm; leave it unspecified");
        }
        return Ok(HashAlgorithm::Unspecified as i32);
    }
    if sign_alg == SignAlgorithm::SignSm2 {
        let h = HashAlgorithm::try_from(hash).unwrap_or(HashAlgorithm::Unspecified);
        return match h {
            HashAlgorithm::Unspecified | HashAlgorithm::HashSm3 => {
                Ok(HashAlgorithm::HashSm3 as i32)
            }
            _ => bail!("SM2 requires SM3 hash algorithm"),
        };
    }
    if hash == HashAlgorithm::Unspecified as i32 {
        bail!("hash algorithm is required");
    }
    Ok(hash)
}
