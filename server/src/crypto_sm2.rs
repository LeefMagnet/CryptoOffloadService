//! SM2 签名/验签与密钥生成（对齐 PkiSdk `sm2_signer.cpp` / `ecc_keypair.cpp`）。
//!
//! 密钥类型识别见 [`crate::pkey_util`]。

use std::ptr;

use anyhow::{bail, Context, Result};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use openssl::x509::{X509Builder, X509NameBuilder};
use openssl_sys::{
    EVP_DigestSign, EVP_DigestSignInit, EVP_DigestVerify, EVP_DigestVerifyInit, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_id,
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid, EVP_PKEY_keygen, EVP_PKEY_EC, EVP_sm3, NID_sm2,
};

/// 国标默认 SM2 签名者 ID（与 PkiSdk `Configure::GetGmUserId` 一致）。
pub const GM_DEFAULT_USER_ID: &[u8] = b"1234567812345678";

#[link(name = "crypto")]
extern "C" {
    fn EVP_MD_CTX_set_pkey_ctx(ctx: *mut openssl_sys::EVP_MD_CTX, pctx: *mut openssl_sys::EVP_PKEY_CTX) -> std::os::raw::c_int;
    fn EVP_PKEY_keygen_init(ctx: *mut openssl_sys::EVP_PKEY_CTX) -> std::os::raw::c_int;
    fn EVP_PKEY_CTX_set1_id(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
        id: *const std::os::raw::c_void,
        len: std::os::raw::c_int,
    ) -> std::os::raw::c_int;
}

/// 生成 SM2 密钥对 + 自签证书 PEM（`EVP_PKEY_keygen` + SM3 签证书）。
pub fn generate_keypair_pem() -> Result<(Vec<u8>, Vec<u8>)> {
    let pkey = generate_private_key()?;
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

/// 测试与 benchmark 沿用名称。
pub fn generate_sm2_pem() -> Result<(Vec<u8>, Vec<u8>)> {
    generate_keypair_pem()
}

fn generate_private_key() -> Result<PKey<Private>> {
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

pub fn sm2_sign(private: &PKeyRef<Private>, data: &[u8]) -> Result<Vec<u8>> {
    sm2_sign_with_user_id(private, data, GM_DEFAULT_USER_ID)
}

pub fn sm2_verify(public: &PKeyRef<Public>, data: &[u8], signature: &[u8]) -> Result<bool> {
    sm2_verify_with_user_id(public, data, signature, GM_DEFAULT_USER_ID)
}

pub fn sm2_sign_with_user_id(
    private: &PKeyRef<Private>,
    data: &[u8],
    user_id: &[u8],
) -> Result<Vec<u8>> {
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

        if EVP_PKEY_CTX_set1_id(pctx, user_id.as_ptr().cast(), user_id.len() as i32) <= 0 {
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

pub fn sm2_verify_with_user_id(
    public: &PKeyRef<Public>,
    data: &[u8],
    signature: &[u8],
    user_id: &[u8],
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

        if EVP_PKEY_CTX_set1_id(pctx, user_id.as_ptr().cast(), user_id.len() as i32) <= 0 {
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
