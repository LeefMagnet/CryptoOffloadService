//! SM2 签名/验签与密钥生成（对齐 PkiSdk `sm2_signer.cpp` / `ecc_keypair.cpp`）。
//!
//! - 密钥：`EVP_PKEY_EC` + `NID_sm2` 曲线 keygen
//! - 签名：`EVP_sm3` + `EVP_PKEY_CTX_set1_id`（默认 GM UserId `1234567812345678`）
//! - 类型：`EVP_PKEY_get0_type_name`（OpenSSL 3.x，PKCS#8 导入后仍可为 "SM2"）

use std::ffi::CStr;
use std::ptr;

use anyhow::{bail, Context, Result};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, Id, PKey, PKeyRef, Private, Public};
use openssl::x509::{X509Builder, X509NameBuilder};
use openssl_sys::{
    EVP_DigestSign, EVP_DigestSignInit, EVP_DigestVerify, EVP_DigestVerifyInit, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_id,
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid, EVP_PKEY_keygen, EVP_PKEY_EC, EVP_sm3, NID_sm2,
};

/// 国标默认 SM2 签名者 ID（与 PkiSdk `Configure::GetGmUserId` 一致）。
pub const SM2_DEFAULT_ID: &[u8] = b"1234567812345678";

#[link(name = "crypto")]
extern "C" {
    fn EVP_PKEY_get0_type_name(pkey: *const openssl_sys::EVP_PKEY) -> *const std::os::raw::c_char;
    fn EVP_MD_CTX_set_pkey_ctx(ctx: *mut openssl_sys::EVP_MD_CTX, pctx: *mut openssl_sys::EVP_PKEY_CTX) -> std::os::raw::c_int;
    fn EVP_PKEY_keygen_init(ctx: *mut openssl_sys::EVP_PKEY_CTX) -> std::os::raw::c_int;
    fn EVP_PKEY_CTX_set1_id(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        id: *const std::os::raw::c_void,
        len: std::os::raw::c_int,
    ) -> std::os::raw::c_int;
}

/// OpenSSL 3.x 密钥类型名（如 "SM2" / "EC" / "RSA"）。
pub fn pkey_type_name<T: HasPublic>(key: &PKey<T>) -> Option<String> {
    pkey_type_name_ref(key)
}

pub fn pkey_type_name_ref(key: &PKeyRef<impl HasPublic>) -> Option<String> {
    unsafe {
        let ptr = EVP_PKEY_get0_type_name(key.as_ptr());
        if ptr.is_null() {
            return None;
        }
        Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
    }
}

pub fn is_sm2_pkey<T: HasPublic>(key: &PKey<T>) -> bool {
    is_sm2_pkey_ref(key)
}

pub fn is_sm2_pkey_ref(key: &PKeyRef<impl HasPublic>) -> bool {
    if key.id() == Id::SM2 {
        return true;
    }
    if pkey_type_name_ref(key)
        .is_some_and(|n| n.eq_ignore_ascii_case("sm2"))
    {
        return true;
    }
    key.ec_key()
        .ok()
        .and_then(|ec| ec.group().curve_name())
        .is_some_and(|nid| nid == Nid::SM2)
}

/// 生成 SM2 密钥对 + 自签证书 PEM（`EVP_PKEY_keygen` + SM3 签证书）。
pub fn generate_sm2_pem() -> Result<(Vec<u8>, Vec<u8>)> {
    let pkey = generate_sm2_pkey()?;
    let priv_pem = pkey.private_key_to_pem_pkcs8()?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "sm2-test")?;
    let name = name.build();

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&pkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.sign(&pkey, MessageDigest::sm3())?;
    let cert_pem = builder.build().to_pem()?;
    Ok((priv_pem, cert_pem))
}

fn generate_sm2_pkey() -> Result<PKey<Private>> {
    unsafe {
        let ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ptr::null_mut());
        if ctx.is_null() {
            bail!("EVP_PKEY_CTX_new_id(EC) failed");
        }
        let ctx_guard = PkeyCtxGuard(ctx);
        if EVP_PKEY_keygen_init(ctx) <= 0 {
            bail!("EVP_PKEY_keygen_init failed");
        }
        if EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_sm2) <= 0 {
            bail!("EVP_PKEY_CTX_set_ec_paramgen_curve_nid(SM2) failed");
        }
        let mut raw: *mut openssl_sys::EVP_PKEY = ptr::null_mut();
        if EVP_PKEY_keygen(ctx, &mut raw) <= 0 {
            bail!("EVP_PKEY_keygen(SM2) failed");
        }
        if raw.is_null() {
            bail!("EVP_PKEY_keygen returned null");
        }
        Ok(PKey::from_ptr(raw))
    }
}

pub fn sign(private: &PKeyRef<Private>, data: &[u8]) -> Result<Vec<u8>> {
    sign_with_id(private, data, SM2_DEFAULT_ID)
}

pub fn verify(public: &PKeyRef<Public>, data: &[u8], signature: &[u8]) -> Result<bool> {
    verify_with_id(public, data, signature, SM2_DEFAULT_ID)
}

pub fn sign_with_id(private: &PKeyRef<Private>, data: &[u8], id: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mctx = EVP_MD_CTX_new();
        if mctx.is_null() {
            bail!("EVP_MD_CTX_new failed");
        }
        let mctx_guard = MdCtxGuard(mctx);

        let pctx = EVP_PKEY_CTX_new(private.as_ptr(), ptr::null_mut());
        if pctx.is_null() {
            bail!("EVP_PKEY_CTX_new failed");
        }
        let pctx_guard = PkeyCtxGuard(pctx);

        if EVP_PKEY_CTX_set1_id(pctx, id.as_ptr().cast(), id.len() as i32) <= 0 {
            bail!("EVP_PKEY_CTX_set1_id failed");
        }
        if EVP_MD_CTX_set_pkey_ctx(mctx, pctx) <= 0 {
            bail!("EVP_MD_CTX_set_pkey_ctx failed");
        }
        if EVP_DigestSignInit(mctx, ptr::null_mut(), EVP_sm3(), ptr::null_mut(), private.as_ptr())
            <= 0
        {
            bail!("EVP_DigestSignInit(SM3) failed");
        }

        let mut sig_len: usize = 0;
        if EVP_DigestSign(mctx, ptr::null_mut(), &mut sig_len, data.as_ptr(), data.len()) <= 0 {
            bail!("EVP_DigestSign(size) failed");
        }
        let mut sig = vec![0u8; sig_len];
        if EVP_DigestSign(
            mctx,
            sig.as_mut_ptr(),
            &mut sig_len,
            data.as_ptr(),
            data.len(),
        ) <= 0
        {
            bail!("EVP_DigestSign failed");
        }
        sig.truncate(sig_len);
        Ok(sig)
    }
}

pub fn verify_with_id(
    public: &PKeyRef<Public>,
    data: &[u8],
    signature: &[u8],
    id: &[u8],
) -> Result<bool> {
    unsafe {
        let mctx = EVP_MD_CTX_new();
        if mctx.is_null() {
            bail!("EVP_MD_CTX_new failed");
        }
        let mctx_guard = MdCtxGuard(mctx);

        let pctx = EVP_PKEY_CTX_new(public.as_ptr(), ptr::null_mut());
        if pctx.is_null() {
            bail!("EVP_PKEY_CTX_new failed");
        }
        let pctx_guard = PkeyCtxGuard(pctx);

        if EVP_PKEY_CTX_set1_id(pctx, id.as_ptr().cast(), id.len() as i32) <= 0 {
            bail!("EVP_PKEY_CTX_set1_id failed");
        }
        if EVP_MD_CTX_set_pkey_ctx(mctx, pctx) <= 0 {
            bail!("EVP_MD_CTX_set_pkey_ctx failed");
        }
        // 与 PkiSdk 一致：验签 init 时 md 传 null
        if EVP_DigestVerifyInit(
            mctx,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            public.as_ptr(),
        ) <= 0
        {
            bail!("EVP_DigestVerifyInit failed");
        }

        let ok = EVP_DigestVerify(
            mctx,
            signature.as_ptr(),
            signature.len(),
            data.as_ptr(),
            data.len(),
        );
        match ok {
            1 => Ok(true),
            0 => Ok(false),
            _ => bail!("EVP_DigestVerify error"),
        }
    }
}

struct MdCtxGuard(*mut openssl_sys::EVP_MD_CTX);
impl Drop for MdCtxGuard {
    fn drop(&mut self) {
        unsafe {
            EVP_MD_CTX_free(self.0);
        }
    }
}

struct PkeyCtxGuard(*mut openssl_sys::EVP_PKEY_CTX);
impl Drop for PkeyCtxGuard {
    fn drop(&mut self) {
        unsafe {
            EVP_PKEY_CTX_free(self.0);
        }
    }
}
