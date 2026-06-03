use anyhow::{anyhow, bail, Context, Result};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};

use crate::pkey_util::{self, KeyFamily};
use openssl::x509::X509;
use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};
use uuid::Uuid;

use crate::pb::{HashAlgorithm, KeyFormat, KeyKind, KeyLifetime, KeyMetadata, SignAlgorithm};

/// 进程内密钥仓库（**内存态，非磁盘持久化**）。
///
/// # 导入时一次性解析（ImportKey）
///
/// 客户端传入 PEM/DER 后，本模块在 `import_key` 中**仅解析一次**：
/// - PEM：`PKey::private_key_from_pem`（内部完成 Base64 解码 + ASN.1 解析）
/// - DER：`PKey::private_key_from_der`
///
/// 解析结果保存为 OpenSSL 原生结构 [`PKey`] / [`X509`]，存入 `HashMap<key_id, StoredKey>`。
///
/// # 后续运算（Sign / Verify / CMS）
///
/// 仅通过 `key_id` 克隆/借用已解析的 `PKey`，**不会**再次解析 PEM/DER 或做 Base64 解码。
/// 这避免了热路径上的重复解析开销；客户端也只需在启动或密钥轮换时调用 ImportKey。
///
/// # 生命周期
///
/// - `PERMANENT`：保留在内存直到 DeleteKey 或服务重启
/// - `TEMPORARY`：首次 `access_key` 用于密码运算后从 map 移除
#[derive(Clone)]
pub struct KeyStore {
    inner: Arc<RwLock<HashMap<String, StoredKey>>>,
}

#[derive(Clone)]
pub(crate) enum KeyMaterial {
    Private {
        key: PKey<Private>,
        cert: Option<X509>,
    },
    Public {
        key: PKey<Public>,
        cert: Option<X509>,
    },
}

impl KeyMaterial {
    fn family(&self) -> KeyFamily {
        match self {
            KeyMaterial::Private { key, .. } | KeyMaterial::Public { key, .. } => {
                pkey_util::family(key)
            }
        }
    }

    fn algorithm_and_bits(&self) -> (String, i32) {
        match self {
            KeyMaterial::Private { key, .. } | KeyMaterial::Public { key, .. } => {
                (pkey_util::algorithm_name(key), key.bits() as i32)
            }
        }
    }
}

struct StoredKey {
    metadata: KeyMetadata,
    material: KeyMaterial,
}

#[derive(Clone)]
pub enum KeyAccess {
    Permanent(KeyMaterial),
    Temporary(KeyMaterial),
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn import_key(
        &self,
        kind: i32,
        lifetime: i32,
        format: i32,
        key_data: &[u8],
        label: &str,
        certificate_data: &[u8],
        certificate_format: i32,
    ) -> Result<KeyMetadata> {
        let kind = KeyKind::try_from(kind).unwrap_or(KeyKind::Unspecified);
        let lifetime = KeyLifetime::try_from(lifetime).unwrap_or(KeyLifetime::Unspecified);
        let format = KeyFormat::try_from(format).unwrap_or(KeyFormat::Unspecified);

        if kind == KeyKind::Unspecified {
            bail!("key kind is required");
        }
        if lifetime == KeyLifetime::Unspecified {
            bail!("key lifetime is required");
        }
        if format == KeyFormat::Unspecified {
            bail!("key format is required");
        }
        if key_data.is_empty() && certificate_data.is_empty() {
            bail!("key_data or certificate_data is required");
        }

        let cert = if certificate_data.is_empty() {
            None
        } else {
            Some(parse_certificate(certificate_data, certificate_format)?)
        };

        let material = match kind {
            KeyKind::Private => {
                let key = parse_private_key(key_data, format as i32)?;
                KeyMaterial::Private { key, cert }
            }
            KeyKind::Public => {
                let key = parse_public_key(key_data, format as i32)?;
                KeyMaterial::Public { key, cert }
            }
            KeyKind::Certificate => {
                let cert = cert.ok_or_else(|| anyhow!("certificate_data is required"))?;
                let key = cert
                    .public_key()
                    .context("failed to extract public key from certificate")?;
                KeyMaterial::Public {
                    key,
                    cert: Some(cert),
                }
            }
            KeyKind::Unspecified => unreachable!(),
        };

        let (algorithm, key_bits) = describe_key(&material);
        let key_id = Uuid::new_v4().to_string();
        let metadata = KeyMetadata {
            key_id: key_id.clone(),
            kind: kind as i32,
            lifetime: lifetime as i32,
            label: label.to_string(),
            algorithm,
            key_bits,
            used: false,
        };

        let mut guard = self
            .inner
            .write()
            .map_err(lock_poisoned)
            .context("import key")?;
        guard.insert(
            key_id.clone(),
            StoredKey {
                metadata: metadata.clone(),
                material,
            },
        );
        Ok(metadata)
    }

    pub fn delete_key(&self, key_id: &str) -> Result<bool> {
        let mut guard = self
            .inner
            .write()
            .map_err(lock_poisoned)
            .context("delete key")?;
        Ok(guard.remove(key_id).is_some())
    }

    pub fn get_metadata(&self, key_id: &str) -> Result<KeyMetadata> {
        let guard = self
            .inner
            .read()
            .map_err(lock_poisoned)
            .context("get key metadata")?;
        guard
            .get(key_id)
            .map(|entry| entry.metadata.clone())
            .ok_or_else(|| anyhow!("key not found: {key_id}"))
    }

    pub fn list_metadata(&self) -> Result<Vec<KeyMetadata>> {
        let guard = self
            .inner
            .read()
            .map_err(lock_poisoned)
            .context("list keys")?;
        Ok(guard.values().map(|entry| entry.metadata.clone()).collect())
    }

    /// 获取密钥用于密码运算。临时密钥在成功返回后从存储中移除（单次有效）。
    pub fn access_key(&self, key_id: &str) -> Result<KeyAccess> {
        let mut guard = self
            .inner
            .write()
            .map_err(lock_poisoned)
            .context("access key")?;
        let entry = guard
            .get_mut(key_id)
            .ok_or_else(|| anyhow!("key not found: {key_id}"))?;

        if entry.metadata.used && entry.metadata.lifetime == KeyLifetime::Temporary as i32 {
            bail!("temporary key already consumed: {key_id}");
        }

        let lifetime =
            KeyLifetime::try_from(entry.metadata.lifetime).unwrap_or(KeyLifetime::Unspecified);
        entry.metadata.used = true;
        let material = entry.material.clone();

        if lifetime == KeyLifetime::Temporary {
            guard.remove(key_id);
            Ok(KeyAccess::Temporary(material))
        } else {
            Ok(KeyAccess::Permanent(material))
        }
    }
}

fn lock_poisoned<T>(err: PoisonError<T>) -> anyhow::Error {
    anyhow!("key store lock poisoned: {err}")
}

fn parse_private_key(data: &[u8], format: i32) -> Result<PKey<Private>> {
    match KeyFormat::try_from(format).unwrap_or(KeyFormat::Unspecified) {
        KeyFormat::Der => PKey::private_key_from_der(data).context("parse private key DER"),
        KeyFormat::Pem => PKey::private_key_from_pem(data).context("parse private key PEM"),
        KeyFormat::Unspecified => bail!("key format is required"),
    }
}

fn parse_public_key(data: &[u8], format: i32) -> Result<PKey<Public>> {
    match KeyFormat::try_from(format).unwrap_or(KeyFormat::Unspecified) {
        KeyFormat::Der => PKey::public_key_from_der(data).context("parse public key DER"),
        KeyFormat::Pem => PKey::public_key_from_pem(data).context("parse public key PEM"),
        KeyFormat::Unspecified => bail!("key format is required"),
    }
}

fn parse_certificate(data: &[u8], format: i32) -> Result<X509> {
    let format = if format == KeyFormat::Unspecified as i32 {
        if data.starts_with(b"-----") {
            KeyFormat::Pem as i32
        } else {
            KeyFormat::Der as i32
        }
    } else {
        format
    };
    match KeyFormat::try_from(format).unwrap_or(KeyFormat::Unspecified) {
        KeyFormat::Der => X509::from_der(data).context("parse certificate DER"),
        KeyFormat::Pem => X509::from_pem(data).context("parse certificate PEM"),
        KeyFormat::Unspecified => bail!("certificate format is required"),
    }
}

fn describe_key(material: &KeyMaterial) -> (String, i32) {
    material.algorithm_and_bits()
}

pub fn hash_algorithm_to_md(hash: i32) -> Result<MessageDigest> {
    match HashAlgorithm::try_from(hash).unwrap_or(HashAlgorithm::Unspecified) {
        HashAlgorithm::HashSha256 => Ok(MessageDigest::sha256()),
        HashAlgorithm::HashSha384 => Ok(MessageDigest::sha384()),
        HashAlgorithm::HashSha512 => Ok(MessageDigest::sha512()),
        HashAlgorithm::HashSha1 => Ok(MessageDigest::sha1()),
        HashAlgorithm::HashSm3 => Ok(MessageDigest::sm3()),
        HashAlgorithm::Unspecified => bail!("hash algorithm is required"),
    }
}

/// SM2 签名须使用 SM3；Ed25519 不使用外部摘要；其余算法须指定 hash。
pub fn resolve_hash_algorithm(hash: i32, sign_alg: SignAlgorithm) -> Result<i32> {
    pkey_util::resolve_hash_for_sign(hash, sign_alg).map_err(Into::into)
}

pub fn infer_sign_algorithm(material: &KeyMaterial, requested: i32) -> Result<SignAlgorithm> {
    let req = if requested != SignAlgorithm::Unspecified as i32 {
        SignAlgorithm::try_from(requested).map_err(|_| anyhow!("invalid sign algorithm"))?
    } else {
        SignAlgorithm::Unspecified
    };
    pkey_util::resolve_sign_algorithm(material.family(), req)
        .map_err(Into::into)
}

pub fn ensure_private(material: &KeyMaterial) -> Result<&PKey<Private>> {
    match material {
        KeyMaterial::Private { key, .. } => Ok(key),
        KeyMaterial::Public { .. } => bail!("operation requires a private key"),
    }
}

pub fn ensure_public(material: &KeyMaterial) -> Result<&PKey<Public>> {
    match material {
        KeyMaterial::Public { key, .. } => Ok(key),
        KeyMaterial::Private { .. } => bail!("operation requires a public key"),
    }
}

pub fn signing_cert(material: &KeyMaterial) -> Result<X509> {
    match material {
        KeyMaterial::Private {
            cert: Some(cert), ..
        } => Ok(cert.clone()),
        KeyMaterial::Private { cert: None, .. } => {
            bail!("CMS build requires certificate imported with private key")
        }
        _ => bail!("CMS build requires a private key with certificate"),
    }
}

pub fn ca_private_with_cert(material: &KeyMaterial) -> Result<(PKey<Private>, X509)> {
    match material {
        KeyMaterial::Private {
            key,
            cert: Some(cert),
        } => Ok((key.clone(), cert.clone())),
        KeyMaterial::Private { cert: None, .. } => {
            bail!("SCEP CA requires certificate imported with private key")
        }
        KeyMaterial::Public { .. } => bail!("SCEP CA requires a private key"),
    }
}

/// CMP 保护验签要求可用证书链入口；仅接受带证书的密钥条目。
pub fn verifying_cert(material: &KeyMaterial) -> Result<X509> {
    match material {
        KeyMaterial::Public {
            cert: Some(cert), ..
        }
        | KeyMaterial::Private {
            cert: Some(cert), ..
        } => Ok(cert.clone()),
        _ => bail!(
            "CMP verify requires certificate-backed key (import KeyKind::Certificate or include certificate_data)"
        ),
    }
}
