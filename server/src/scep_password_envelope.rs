//! CMS EnvelopedData with `PasswordRecipientInfo` (RFC 8894 §3.1 / CMS §6.2.4).
//!
//! Used when the recipient public key is not encryption-capable (e.g. ECDSA-only wrapper);
//! the shared `challengePassword` from PKCS#10 enrolment encrypts `messageData`.
//!
//! Flow matches `openssl cms -encrypt -pwri_password` (OpenSSL `apps/cms.c`).

use anyhow::{bail, Context, Result};
use openssl::symm::Cipher;
use openssl_sys as ffi;
use std::os::raw::{c_int, c_uint, c_void};
use std::ptr;

const CMS_BINARY: c_uint = 0x0080;
const CMS_PARTIAL: c_uint = 0x4000;
const CMS_RECIPINFO_PASS: c_int = 3;

/// RFC 8894 §7.3: high-entropy shared secret; cap wire size.
pub const MAX_CHALLENGE_PASSWORD_LEN: usize = 256;

#[link(name = "crypto")]
extern "C" {
    fn CMS_add0_recipient_password(
        cms: *mut ffi::CMS_ContentInfo,
        iter: c_int,
        wrap_nid: c_int,
        pbe_nid: c_int,
        pass: *mut u8,
        passlen: isize,
        kekcipher: *const ffi::EVP_CIPHER,
    ) -> *mut c_void;

    fn CMS_get0_RecipientInfos(cms: *mut ffi::CMS_ContentInfo) -> *mut c_void;

    fn CMS_RecipientInfo_type(ri: *mut c_void) -> c_int;

    fn CMS_decrypt_set1_password(
        cms: *mut ffi::CMS_ContentInfo,
        pass: *mut u8,
        passlen: isize,
    ) -> c_int;

    fn CMS_final(
        cms: *mut ffi::CMS_ContentInfo,
        data: *mut ffi::BIO,
        dcont: *mut ffi::BIO,
        flags: c_uint,
    ) -> c_int;

    fn OPENSSL_sk_num(st: *const c_void) -> c_int;
    fn OPENSSL_sk_value(st: *const c_void, i: c_int) -> *mut c_void;
}

pub fn validate_challenge_password(password: &str) -> Result<()> {
    if password.is_empty() {
        bail!("challenge_password must not be empty");
    }
    if password.len() > MAX_CHALLENGE_PASSWORD_LEN {
        bail!("challenge_password too long (max {MAX_CHALLENGE_PASSWORD_LEN})");
    }
    if password.bytes().any(|b| b == 0) {
        bail!("challenge_password must not contain NUL bytes");
    }
    Ok(())
}

/// Build EnvelopedData DER using `PasswordRecipientInfo` + PBKDF2 (OpenSSL default pwri path).
pub fn encrypt_envelope_password(
    plaintext: &[u8],
    password: &str,
    cipher: Cipher,
) -> Result<Vec<u8>> {
    validate_challenge_password(password)?;
    unsafe {
        ffi::init();
        let in_bio = mem_bio_from_bytes(plaintext).context("CMS input BIO")?;
        let flags = CMS_BINARY | CMS_PARTIAL;

        let cms = ffi::CMS_encrypt(ptr::null_mut(), in_bio, cipher.as_ptr(), flags);
        if cms.is_null() {
            ffi::BIO_free_all(in_bio);
            bail!("CMS_encrypt failed: {}", openssl_error());
        }

        let pwri_tmp = strdup_password(password)?;
        let ri = CMS_add0_recipient_password(
            cms,
            -1,
            ffi::NID_undef,
            ffi::NID_undef,
            pwri_tmp,
            -1,
            ptr::null(),
        );
        if ri.is_null() {
            ffi::OPENSSL_free(pwri_tmp as *mut _);
            ffi::CMS_ContentInfo_free(cms);
            ffi::BIO_free_all(in_bio);
            bail!("CMS_add0_recipient_password failed: {}", openssl_error());
        }

        if CMS_final(cms, in_bio, ptr::null_mut(), flags) != 1 {
            ffi::CMS_ContentInfo_free(cms);
            ffi::BIO_free_all(in_bio);
            bail!("CMS_final failed: {}", openssl_error());
        }

        let der = cms_to_der(cms)?;
        ffi::CMS_ContentInfo_free(cms);
        ffi::BIO_free_all(in_bio);
        Ok(der)
    }
}

/// Decrypt EnvelopedData protected with `PasswordRecipientInfo`.
pub fn decrypt_envelope_password(enveloped_der: &[u8], password: &str) -> Result<Vec<u8>> {
    validate_challenge_password(password)?;
    unsafe {
        ffi::init();
        let cms = cms_from_der(enveloped_der)?;
        let result = decrypt_cms_password(cms, password);
        ffi::CMS_ContentInfo_free(cms);
        result
    }
}

/// Returns true when any CMS recipient is `PasswordRecipientInfo`.
///
/// Some senders may include multiple recipients (mixed recipient types),
/// so we must scan the full recipient set instead of checking index 0 only.
pub fn enveloped_uses_password_recipient(enveloped_der: &[u8]) -> Result<bool> {
    unsafe {
        ffi::init();
        let cms = cms_from_der(enveloped_der)?;
        let uses = first_recipient_is_password(cms);
        ffi::CMS_ContentInfo_free(cms);
        uses
    }
}

unsafe fn first_recipient_is_password(cms: *mut ffi::CMS_ContentInfo) -> Result<bool> {
    let infos = CMS_get0_RecipientInfos(cms);
    if infos.is_null() {
        return Ok(false);
    }
    let count = OPENSSL_sk_num(infos);
    if count <= 0 {
        return Ok(false);
    }
    for i in 0..count {
        let ri = OPENSSL_sk_value(infos, i);
        if !ri.is_null() && CMS_RecipientInfo_type(ri) == CMS_RECIPINFO_PASS {
            return Ok(true);
        }
    }
    Ok(false)
}

unsafe fn decrypt_cms_password(cms: *mut ffi::CMS_ContentInfo, password: &str) -> Result<Vec<u8>> {
    if !first_recipient_is_password(cms)? {
        bail!("CMS recipient is not PasswordRecipientInfo");
    }

    let pass = password.as_bytes();
    if CMS_decrypt_set1_password(cms, pass.as_ptr() as *mut u8, pass.len() as isize) != 1 {
        bail!("CMS_decrypt_set1_password failed: {}", openssl_error());
    }

    let out_bio = ffi::BIO_new(ffi::BIO_s_mem());
    if out_bio.is_null() {
        bail!("BIO_new for CMS decrypt output");
    }
    if ffi::CMS_decrypt(
        cms,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        out_bio,
        CMS_BINARY,
    ) != 1
    {
        ffi::BIO_free_all(out_bio);
        bail!("CMS_decrypt (password) failed: {}", openssl_error());
    }

    let plain = mem_bio_to_vec(out_bio).context("read decrypted CMS content")?;
    ffi::BIO_free_all(out_bio);
    Ok(plain)
}

/// OpenSSL `CMS_add0_recipient_password` takes ownership of `pass` (see `apps/cms.c`).
unsafe fn strdup_password(password: &str) -> Result<*mut u8> {
    let bytes = password.as_bytes();
    let len = bytes.len() + 1;
    let dup = ffi::CRYPTO_malloc(len, std::ptr::null(), 0);
    if dup.is_null() {
        bail!("CRYPTO_malloc failed");
    }
    let dup_u8 = dup as *mut u8;
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), dup_u8, bytes.len());
    *dup_u8.add(bytes.len()) = 0;
    Ok(dup_u8)
}

unsafe fn mem_bio_from_bytes(data: &[u8]) -> Result<*mut ffi::BIO> {
    let bio = ffi::BIO_new(ffi::BIO_s_mem());
    if bio.is_null() {
        bail!("BIO_new failed");
    }
    if ffi::BIO_write(bio, data.as_ptr() as *const _, data.len() as i32) < 0 {
        ffi::BIO_free_all(bio);
        bail!("BIO_write failed");
    }
    Ok(bio)
}

unsafe fn mem_bio_to_vec(bio: *mut ffi::BIO) -> Result<Vec<u8>> {
    use std::os::raw::c_char;
    let mut cptr: *mut c_char = ptr::null_mut();
    let len = ffi::BIO_get_mem_data(bio, &mut cptr);
    if len < 0 || cptr.is_null() {
        bail!("BIO_get_mem_data failed");
    }
    Ok(std::slice::from_raw_parts(cptr as *const u8, len as usize).to_vec())
}

unsafe fn cms_from_der(der: &[u8]) -> Result<*mut ffi::CMS_ContentInfo> {
    let mut ptr = der.as_ptr();
    let cms = ffi::d2i_CMS_ContentInfo(ptr::null_mut(), &mut ptr, der.len() as i64);
    if cms.is_null() {
        bail!("invalid CMS EnvelopedData DER: {}", openssl_error());
    }
    Ok(cms)
}

unsafe fn cms_to_der(cms: *mut ffi::CMS_ContentInfo) -> Result<Vec<u8>> {
    let mut der_ptr: *mut u8 = ptr::null_mut();
    let len = ffi::i2d_CMS_ContentInfo(cms, &mut der_ptr);
    if len <= 0 || der_ptr.is_null() {
        bail!("i2d_CMS_ContentInfo failed: {}", openssl_error());
    }
    let out = std::slice::from_raw_parts(der_ptr, len as usize).to_vec();
    ffi::OPENSSL_free(der_ptr as *mut _);
    Ok(out)
}

fn openssl_error() -> String {
    let stack = openssl::error::ErrorStack::get();
    if stack.errors().is_empty() {
        "unknown OpenSSL error".into()
    } else {
        format!("{stack}")
    }
}
