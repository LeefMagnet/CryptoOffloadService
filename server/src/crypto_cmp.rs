//! CMP PKIMessage offload（RFC 4210 / 9480 / 9481）。
//!
//! # Architecture
//!
//! - **Dynamic libcrypto**（`libloading`）：解析/验签（`d2i_OSSL_CMP_MSG`、`OSSL_CMP_validate_msg` 等）。
//! - **Static cmp_shim.c**：字段级提取（`protectionAlg`、`senderNonce` 等需要访问 OpenSSL 内部结构）、
//!   构建（`cmp_shim_build_protected_part`、`cmp_shim_build_pki_message`）。
//!
//! 静态 shim 之所以需要访问内部结构体是为了：
//! - 提取 `protectionAlg` OID（`X509_ALGOR` → `OBJ_obj2txt`）
//! - 注入 `protectionAlg` 到 PKIHeader（构建时）
//! - 提取 `protection` BIT STRING 值（剥离 unused-bits 字节）

use anyhow::{bail, Context, Result};
use foreign_types::ForeignType;
use libloading::Library;
use openssl_sys as ffi;
use std::ffi::{c_char, CString};
use std::os::raw::{c_int, c_long, c_uchar, c_void};

use crate::crypto_sign;
use crate::key_store::{verifying_cert, KeyAccess};
use crate::pb::{HashAlgorithm, SignAlgorithm};

// ---------------------------------------------------------------------------
// types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ParsedCmpMessage {
    pub body_type: i32,
    pub protection_alg_oid: String,
    pub protection: Vec<u8>,
    pub protected_part_der: Vec<u8>,
    pub pki_header_der: Vec<u8>,
    pub pki_body_der: Vec<u8>,
    pub transaction_id: Vec<u8>,
    pub sender_nonce: Vec<u8>,
    pub recipient_nonce: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BuildCmpOutput {
    pub pki_message_der: Vec<u8>,
    pub protection_alg_oid: String,
    pub hash_algorithm: i32,
    pub sign_algorithm: i32,
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

/// 解析 PKIMessage DER，提取 header/body/protection/signed 属性等全部字段。
pub fn parse_pki_message(pki_message_der: &[u8]) -> Result<ParsedCmpMessage> {
    ensure_cmp_supported()?;
    if pki_message_der.is_empty() {
        bail!("pki_message_der must not be empty");
    }

    // 1. 拆分 header/body DER（cmp_shim_split 内部 d2i → i2d header → extract body TLV）
    let (header_der, body_der) = split_pki_message(pki_message_der)?;

    // 2. 提取 header 中的字段（protectionAlg OID、senderNonce、transactionID、recipientNonce）
    //    注意：parse_header_fields 返回的是 OPENSSL_malloc 分配的内存，使用后必须释放。
    let (protection_alg_oid, sender_nonce, transaction_id, recipient_nonce) = {
        let (oid, oid_len, sn, sn_len, tx, tx_len, rn, rn_len) = unsafe {
            parse_header_fields(&header_der)?
        };
        let pao = oid_bytes_to_string(oid, oid_len);
        let snv  = ptr_bytes_to_vec(sn, sn_len);
        let txv  = ptr_bytes_to_vec(tx, tx_len);
        let rnv  = ptr_bytes_to_vec(rn, rn_len);
        // 释放 shim 分配的内存
        unsafe {
            if !oid.is_null() { ffi::OPENSSL_free(oid as *mut c_void); }
            if !sn.is_null()  { ffi::OPENSSL_free(sn as *mut c_void); }
            if !tx.is_null()  { ffi::OPENSSL_free(tx as *mut c_void); }
            if !rn.is_null()  { ffi::OPENSSL_free(rn as *mut c_void); }
        }
        (pao, snv, txv, rnv)
    };

    // 3. 提取 body_type（ASN.1 tag number）
    let body_type = unsafe { cmp_shim_get_body_type_raw(
        pki_message_der.as_ptr(),
        pki_message_der.len() as c_int,
    )};

    // 4. 提取 protection 字节（剥离 unused-bits octet）
    let protection = unsafe {
        let mut prot: *mut u8 = std::ptr::null_mut();
        let mut prot_len: c_int = 0;
        let code = cmp_shim_get_protection_raw(
            pki_message_der.as_ptr(),
            pki_message_der.len() as c_int,
            &mut prot,
            &mut prot_len,
        );
        if code != CMP_SHIM_OK || prot.is_null() || prot_len <= 0 {
            Vec::new()
        } else {
            let bytes = std::slice::from_raw_parts(prot as *const u8, prot_len as usize).to_vec();
            ffi::OPENSSL_free(prot as *mut c_void);
            bytes
        }
    };

    // 5. 构建 protected_part_der = DER(SEQUENCE{header, body})，用于验签/签名
    let protected_part_der = cmp_shim_build_protected_part(&header_der, &body_der)
        .context("build protected_part_der")?;

    Ok(ParsedCmpMessage {
        body_type,
        protection_alg_oid,
        protection,
        protected_part_der,
        pki_header_der: header_der,
        pki_body_der: body_der,
        transaction_id,
        sender_nonce,
        recipient_nonce,
    })
}

/// 验证 PKIMessage 的 protection 签名，并返回实际使用的算法信息。
pub fn verify_pki_message_protection(
    access: KeyAccess,
    pki_message_der: &[u8],
    _hash_algorithm: i32,
    _sign_algorithm: i32,
) -> Result<(bool, String, i32, i32)> {
    ensure_cmp_supported()?;
    let api = load_cmp_api()?;

    // 先解析出 protection_alg_oid（用于返回值；验签由 OpenSSL CMP 内部完成）
    let (header_der, _body_der) = split_pki_message(pki_message_der)?;
    let protection_alg_oid = {
        let (oid, oid_len, sn, _sn_len, _tx, _tx_len, _rn, _rn_len) =
            unsafe { parse_header_fields(&header_der)? };
        let pao = oid_bytes_to_string(oid, oid_len);
        unsafe {
            if !oid.is_null() { ffi::OPENSSL_free(oid as *mut c_void); }
            if !sn.is_null()  { ffi::OPENSSL_free(sn as *mut c_void); }
        }
        pao
    };
    let (effective_hash, effective_sign) =
        protection_alg_oid_to_algs(&protection_alg_oid);

    let cert = match access {
        KeyAccess::Permanent(m) | KeyAccess::Temporary(m) => verifying_cert(&m)?,
    };

    unsafe {
        let mut p = pki_message_der.as_ptr();
        let mut out: *mut OsslCmpMsg = std::ptr::null_mut();
        let msg = (api.d2i_cmp_msg)(&mut out, &mut p, pki_message_der.len() as c_long);
        if msg.is_null() {
            bail!("d2i_OSSL_CMP_MSG failed");
        }
        let ctx = (api.cmp_ctx_new)(std::ptr::null_mut(), std::ptr::null());
        if ctx.is_null() {
            (api.cmp_msg_free)(msg);
            bail!("OSSL_CMP_CTX_new failed");
        }

        let mut store_builder = openssl::x509::store::X509StoreBuilder::new()?;
        store_builder.add_cert(cert)?;
        let store = store_builder.build();
        let store_ptr = store.as_ptr() as *mut ffi::X509_STORE;
        if (api.cmp_ctx_set0_trusted)(ctx, store_ptr) != 1 {
            (api.cmp_ctx_free)(ctx);
            (api.cmp_msg_free)(msg);
            bail!("OSSL_CMP_CTX_set0_trustedStore failed");
        }
        std::mem::forget(store);

        let ok = (api.cmp_validate_msg)(ctx, msg) == 1;
        (api.cmp_ctx_free)(ctx);
        (api.cmp_msg_free)(msg);

        Ok((ok, protection_alg_oid, effective_hash, effective_sign))
    }
}

/// 构建带 protection 的 PKIMessage：header + body → 签名 → 组装。
pub fn build_protected_pki_message(
    access: KeyAccess,
    pki_header_der: &[u8],
    pki_body_der: &[u8],
    hash_algorithm: i32,
    sign_algorithm: i32,
) -> Result<BuildCmpOutput> {
    ensure_cmp_supported()?;
    let protected_part_der = cmp_shim_build_protected_part(pki_header_der, pki_body_der)?;
    let sign_out = crypto_sign::sign(access, &protected_part_der, hash_algorithm, sign_algorithm)?;
    let protection_alg_oid =
        protection_alg_oid_for(sign_out.sign_algorithm, sign_out.hash_algorithm)?;
    let pki_message_der = cmp_shim_build_pki_message(
        pki_header_der,
        pki_body_der,
        &protection_alg_oid,
        &sign_out.signature,
    )?;
    Ok(BuildCmpOutput {
        pki_message_der,
        protection_alg_oid,
        hash_algorithm: sign_out.hash_algorithm,
        sign_algorithm: sign_out.sign_algorithm,
    })
}

/// 检查 libcrypto 是否加载了 CMP 符号。
pub fn ensure_cmp_supported() -> Result<()> {
    let _ = load_cmp_api()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// OID ↔ 算法映射
// ---------------------------------------------------------------------------

/// Sign/Hash → protectionAlg OID（构建方向）。
pub fn protection_alg_oid_for(sign_algorithm: i32, hash_algorithm: i32) -> Result<String> {
    let sign = SignAlgorithm::try_from(sign_algorithm)
        .map_err(|_| anyhow::anyhow!("invalid sign algorithm"))?;
    let hash = HashAlgorithm::try_from(hash_algorithm).unwrap_or(HashAlgorithm::Unspecified);
    let oid = match (sign, hash) {
        (SignAlgorithm::SignRsaPkcs1V15, HashAlgorithm::HashSha256) => "1.2.840.113549.1.1.11",
        (SignAlgorithm::SignRsaPkcs1V15, HashAlgorithm::HashSha384) => "1.2.840.113549.1.1.12",
        (SignAlgorithm::SignRsaPkcs1V15, HashAlgorithm::HashSha512) => "1.2.840.113549.1.1.13",
        (SignAlgorithm::SignRsaPkcs1V15, HashAlgorithm::HashSha1) => "1.2.840.113549.1.1.5",
        (SignAlgorithm::SignEcdsa, HashAlgorithm::HashSha256) => "1.2.840.10045.4.3.2",
        (SignAlgorithm::SignEcdsa, HashAlgorithm::HashSha384) => "1.2.840.10045.4.3.3",
        (SignAlgorithm::SignEcdsa, HashAlgorithm::HashSha512) => "1.2.840.10045.4.3.4",
        (SignAlgorithm::SignSm2, HashAlgorithm::HashSm3) => "1.2.156.10197.1.501",
        (SignAlgorithm::SignEd25519, HashAlgorithm::Unspecified) => "1.3.101.112",
        (SignAlgorithm::SignRsaPss, _) => "1.2.840.113549.1.1.10",
        _ => bail!("unsupported sign/hash combination for CMP protection OID"),
    };
    Ok(oid.to_string())
}

/// protectionAlg OID → (HashAlgorithm, SignAlgorithm)（解析/验签方向）。
pub fn protection_alg_oid_to_algs(oid: &str) -> (i32, i32) {
    match oid {
        "1.2.840.113549.1.1.11" => (HashAlgorithm::HashSha256 as i32, SignAlgorithm::SignRsaPkcs1V15 as i32),
        "1.2.840.113549.1.1.12" => (HashAlgorithm::HashSha384 as i32, SignAlgorithm::SignRsaPkcs1V15 as i32),
        "1.2.840.113549.1.1.13" => (HashAlgorithm::HashSha512 as i32, SignAlgorithm::SignRsaPkcs1V15 as i32),
        "1.2.840.113549.1.1.5"  => (HashAlgorithm::HashSha1   as i32, SignAlgorithm::SignRsaPkcs1V15 as i32),
        "1.2.840.10045.4.3.2"   => (HashAlgorithm::HashSha256 as i32, SignAlgorithm::SignEcdsa        as i32),
        "1.2.840.10045.4.3.3"   => (HashAlgorithm::HashSha384 as i32, SignAlgorithm::SignEcdsa        as i32),
        "1.2.840.10045.4.3.4"   => (HashAlgorithm::HashSha512 as i32, SignAlgorithm::SignEcdsa        as i32),
        "1.2.156.10197.1.501"   => (HashAlgorithm::HashSm3    as i32, SignAlgorithm::SignSm2          as i32),
        "1.3.101.112"           => (HashAlgorithm::Unspecified as i32, SignAlgorithm::SignEd25519     as i32),
        "1.2.840.113549.1.1.10" => (HashAlgorithm::Unspecified as i32, SignAlgorithm::SignRsaPss      as i32), // PSS hash in params
        _ => (HashAlgorithm::Unspecified as i32, SignAlgorithm::Unspecified as i32),
    }
}

// ---------------------------------------------------------------------------
// dynamic libcrypto loading (CMP-only symbols)
// ---------------------------------------------------------------------------

type D2iCmpMsgFn =
    unsafe extern "C" fn(*mut *mut OsslCmpMsg, *mut *const c_uchar, c_long) -> *mut OsslCmpMsg;
type CmpMsgFreeFn = unsafe extern "C" fn(*mut OsslCmpMsg);
type MsgGet0HeaderFn = unsafe extern "C" fn(*const OsslCmpMsg) -> *mut OsslCmpPkiHeader;
type MsgGetBodyTypeFn = unsafe extern "C" fn(*const OsslCmpMsg) -> c_int;
type I2dCmpPkiHeaderFn = unsafe extern "C" fn(*const OsslCmpPkiHeader, *mut *mut c_uchar) -> c_int;
type HdrGetOctetsFn = unsafe extern "C" fn(*const OsslCmpPkiHeader) -> *mut ffi::ASN1_OCTET_STRING;
type CmpCtxNewFn = unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut OsslCmpCtx;
type CmpCtxFreeFn = unsafe extern "C" fn(*mut OsslCmpCtx);
type CmpCtxSetTrustedFn = unsafe extern "C" fn(*mut OsslCmpCtx, *mut ffi::X509_STORE) -> c_int;
type CmpValidateMsgFn = unsafe extern "C" fn(*mut OsslCmpCtx, *const OsslCmpMsg) -> c_int;

enum OsslCmpMsg {}
enum OsslCmpCtx {}
enum OsslCmpPkiHeader {}

#[allow(dead_code)] // symbols loaded for FFI; some unreferenced after api cleanup
struct CmpApi {
    _lib: Library,
    d2i_cmp_msg: D2iCmpMsgFn,
    cmp_msg_free: CmpMsgFreeFn,
    msg_get0_header: MsgGet0HeaderFn,
    msg_get_bodytype: MsgGetBodyTypeFn,
    i2d_cmp_pkiheader: I2dCmpPkiHeaderFn,
    hdr_get0_transaction_id: HdrGetOctetsFn,
    hdr_get0_recip_nonce: HdrGetOctetsFn,
    cmp_ctx_new: CmpCtxNewFn,
    cmp_ctx_free: CmpCtxFreeFn,
    cmp_ctx_set0_trusted: CmpCtxSetTrustedFn,
    cmp_validate_msg: CmpValidateMsgFn,
}

fn load_cmp_api() -> Result<CmpApi> {
    let candidates: &[&str] = if cfg!(target_os = "windows") {
        &["libcrypto-3-x64.dll", "libcrypto-3.dll", "libcrypto.dll"]
    } else if cfg!(target_os = "macos") {
        &["libcrypto.3.dylib", "libcrypto.dylib"]
    } else {
        &["libcrypto.so.3", "libcrypto.so"]
    };

    for name in candidates {
        let lib = unsafe { Library::new(name) };
        let Ok(lib) = lib else {
            continue;
        };
        unsafe {
            let d2i_cmp_msg: D2iCmpMsgFn = *lib.get(b"d2i_OSSL_CMP_MSG\0")?;
            let cmp_msg_free: CmpMsgFreeFn = *lib.get(b"OSSL_CMP_MSG_free\0")?;
            let msg_get0_header: MsgGet0HeaderFn = *lib.get(b"OSSL_CMP_MSG_get0_header\0")?;
            let msg_get_bodytype: MsgGetBodyTypeFn = *lib.get(b"OSSL_CMP_MSG_get_bodytype\0")?;
            let i2d_cmp_pkiheader: I2dCmpPkiHeaderFn = *lib.get(b"i2d_OSSL_CMP_PKIHEADER\0")?;
            let hdr_get0_transaction_id: HdrGetOctetsFn =
                *lib.get(b"OSSL_CMP_HDR_get0_transactionID\0")?;
            let hdr_get0_recip_nonce: HdrGetOctetsFn =
                *lib.get(b"OSSL_CMP_HDR_get0_recipNonce\0")?;
            let cmp_ctx_new: CmpCtxNewFn = *lib.get(b"OSSL_CMP_CTX_new\0")?;
            let cmp_ctx_free: CmpCtxFreeFn = *lib.get(b"OSSL_CMP_CTX_free\0")?;
            let cmp_ctx_set0_trusted: CmpCtxSetTrustedFn =
                *lib.get(b"OSSL_CMP_CTX_set0_trustedStore\0")?;
            let cmp_validate_msg: CmpValidateMsgFn = *lib.get(b"OSSL_CMP_validate_msg\0")?;
            return Ok(CmpApi {
                _lib: lib,
                d2i_cmp_msg,
                cmp_msg_free,
                msg_get0_header,
                msg_get_bodytype,
                i2d_cmp_pkiheader,
                hdr_get0_transaction_id,
                hdr_get0_recip_nonce,
                cmp_ctx_new,
                cmp_ctx_free,
                cmp_ctx_set0_trusted,
                cmp_validate_msg,
            });
        }
    }
    bail!("CMP_OPENSSL_UNSUPPORTED: OpenSSL 3.x with CMP symbols is not available")
}

// ---------------------------------------------------------------------------
// static cmp_shim FFI
// ---------------------------------------------------------------------------

const CMP_SHIM_OK: c_int = 1;

#[link(name = "cmp_shim", kind = "static")]
unsafe extern "C" {
    // -- build helpers (existing) --
    #[link_name = "cmp_shim_build_protected_part"]
    fn cmp_shim_build_protected_part_raw(
        header_der: *const u8, header_der_len: c_int,
        body_der: *const u8, body_der_len: c_int,
        out_der: *mut *mut u8, out_der_len: *mut c_int,
    ) -> c_int;

    #[link_name = "cmp_shim_build_pki_message"]
    fn cmp_shim_build_pki_message_raw(
        header_der: *const u8, header_der_len: c_int,
        body_der: *const u8, body_der_len: c_int,
        protection_alg_oid: *const c_char,
        signature: *const u8, signature_len: c_int,
        out_der: *mut *mut u8, out_der_len: *mut c_int,
    ) -> c_int;

    #[link_name = "cmp_shim_split_pki_message"]
    fn cmp_shim_split_pki_message_raw(
        msg_der: *const u8, msg_der_len: c_int,
        header_der: *mut *mut u8, header_der_len: *mut c_int,
        body_der: *mut *mut u8, body_der_len: *mut c_int,
    ) -> c_int;

    // -- parse helpers (new) --
    #[link_name = "cmp_shim_get_body_type"]
    fn cmp_shim_get_body_type_raw(
        msg_der: *const u8, msg_der_len: c_int,
    ) -> c_int; // returns body_type on success, -1 on error

    #[link_name = "cmp_shim_parse_header_fields"]
    fn cmp_shim_parse_header_fields_raw(
        header_der: *const u8, header_der_len: c_int,
        out_oid: *mut *mut u8, out_oid_len: *mut c_int,
        out_sn: *mut *mut u8, out_sn_len: *mut c_int,
        out_tx: *mut *mut u8, out_tx_len: *mut c_int,
        out_rn: *mut *mut u8, out_rn_len: *mut c_int,
    ) -> c_int;

    #[link_name = "cmp_shim_get_protection"]
    fn cmp_shim_get_protection_raw(
        msg_der: *const u8, msg_der_len: c_int,
        out: *mut *mut u8, out_len: *mut c_int,
    ) -> c_int;
}

/// Split a complete PKIMessage DER into `(header_der, body_der)`.
/// Uses cmp_shim internals: d2i → i2d header → ASN.1-walk body TLV.
pub fn split_pki_message(pki_message_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    unsafe {
        let mut hdr: *mut u8 = std::ptr::null_mut();
        let mut hdr_len: c_int = 0;
        let mut body: *mut u8 = std::ptr::null_mut();
        let mut body_len: c_int = 0;
        let code = cmp_shim_split_pki_message_raw(
            pki_message_der.as_ptr(),
            pki_message_der.len() as c_int,
            &mut hdr, &mut hdr_len,
            &mut body, &mut body_len,
        );
        if code != CMP_SHIM_OK {
            bail!("{}", map_cmp_shim_error("split_pki_message", code));
        }
        let header = std::slice::from_raw_parts(hdr as *const u8, hdr_len as usize).to_vec();
        let body_bytes = std::slice::from_raw_parts(body as *const u8, body_len as usize).to_vec();
        ffi::OPENSSL_free(hdr as *mut c_void);
        ffi::OPENSSL_free(body as *mut c_void);
        Ok((header, body_bytes))
    }
}

/// Parse header fields from PKIHeader DER (via cmp_shim_parse_header_fields).
///
/// Returns raw malloc'd buffers that callers must free with `OPENSSL_free`.
unsafe fn parse_header_fields(header_der: &[u8]) -> Result<(
    *mut u8, c_int, // protection_alg_oid bytes + len
    *mut u8, c_int, // sender_nonce bytes + len
    *mut u8, c_int, // transaction_id bytes + len
    *mut u8, c_int, // recipient_nonce bytes + len
)> {
    let mut oid: *mut u8 = std::ptr::null_mut();
    let mut oid_len: c_int = 0;
    let mut sn: *mut u8 = std::ptr::null_mut();
    let mut sn_len: c_int = 0;
    let mut tx: *mut u8 = std::ptr::null_mut();
    let mut tx_len: c_int = 0;
    let mut rn: *mut u8 = std::ptr::null_mut();
    let mut rn_len: c_int = 0;
    let code = cmp_shim_parse_header_fields_raw(
        header_der.as_ptr(), header_der.len() as c_int,
        &mut oid, &mut oid_len,
        &mut sn, &mut sn_len,
        &mut tx, &mut tx_len,
        &mut rn, &mut rn_len,
    );
    if code != CMP_SHIM_OK {
        // free any partially allocated buffers on error
        if !oid.is_null() { ffi::OPENSSL_free(oid as *mut c_void); }
        if !sn.is_null()  { ffi::OPENSSL_free(sn as *mut c_void); }
        if !tx.is_null()  { ffi::OPENSSL_free(tx as *mut c_void); }
        if !rn.is_null()  { ffi::OPENSSL_free(rn as *mut c_void); }
        bail!("{}", map_cmp_shim_error("parse_header_fields", code));
    }
    Ok((oid, oid_len, sn, sn_len, tx, tx_len, rn, rn_len))
}

fn cmp_shim_build_protected_part(header: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: c_int = 0;
        let code = cmp_shim_build_protected_part_raw(
            header.as_ptr(), header.len() as c_int,
            body.as_ptr(), body.len() as c_int,
            &mut out, &mut out_len,
        );
        if code != CMP_SHIM_OK {
            bail!("{}", map_cmp_shim_error("build_protected_part", code));
        }
        if out.is_null() || out_len <= 0 {
            bail!("CMP_SHIM_INTERNAL(build_protected_part): invalid output buffer");
        }
        let bytes = std::slice::from_raw_parts(out as *const u8, out_len as usize).to_vec();
        ffi::OPENSSL_free(out as *mut c_void);
        Ok(bytes)
    }
}

fn cmp_shim_build_pki_message(
    header: &[u8], body: &[u8], oid: &str, signature: &[u8],
) -> Result<Vec<u8>> {
    let c_oid = CString::new(oid).map_err(|_| anyhow::anyhow!("invalid oid"))?;
    unsafe {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: c_int = 0;
        let code = cmp_shim_build_pki_message_raw(
            header.as_ptr(), header.len() as c_int,
            body.as_ptr(), body.len() as c_int,
            c_oid.as_ptr(),
            signature.as_ptr(), signature.len() as c_int,
            &mut out, &mut out_len,
        );
        if code != CMP_SHIM_OK {
            bail!("{}", map_cmp_shim_error("build_pki_message", code));
        }
        if out.is_null() || out_len <= 0 {
            bail!("CMP_SHIM_INTERNAL(build_pki_message): invalid output buffer");
        }
        let bytes = std::slice::from_raw_parts(out as *const u8, out_len as usize).to_vec();
        ffi::OPENSSL_free(out as *mut c_void);
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// error mapping (shared)
// ---------------------------------------------------------------------------

const CMP_SHIM_ERR_NULL_ARG: c_int = -1;
const CMP_SHIM_ERR_BAD_LENGTH: c_int = -2;
const CMP_SHIM_ERR_HEADER_DER: c_int = -3;
const CMP_SHIM_ERR_BODY_DER: c_int = -4;
const CMP_SHIM_ERR_OID_INVALID: c_int = -5;
const CMP_SHIM_ERR_OPENSSL_ALLOC: c_int = -6;
const CMP_SHIM_ERR_OPENSSL_ENCODE: c_int = -7;
const CMP_SHIM_ERR_MSG_DER: c_int = -8;

fn map_cmp_shim_error(op: &str, code: c_int) -> String {
    match code {
        CMP_SHIM_ERR_NULL_ARG => format!("CMP_SHIM_INVALID_ARGUMENT({op}): null pointer input"),
        CMP_SHIM_ERR_BAD_LENGTH => format!("CMP_SHIM_INVALID_ARGUMENT({op}): invalid DER/signature length"),
        CMP_SHIM_ERR_HEADER_DER => format!(
            "CMP_SHIM_INVALID_ARGUMENT({op}): pki_header_der must be valid PKIHeader"
        ),
        CMP_SHIM_ERR_BODY_DER => format!(
            "CMP_SHIM_INVALID_ARGUMENT({op}): pki_body_der must be valid PKIBody"
        ),
        CMP_SHIM_ERR_MSG_DER => format!(
            "CMP_SHIM_INVALID_ARGUMENT({op}): pki_message_der must be valid PKIMessage"
        ),
        CMP_SHIM_ERR_OID_INVALID => format!("CMP_SHIM_INVALID_ARGUMENT({op}): invalid protection algorithm oid"),
        CMP_SHIM_ERR_OPENSSL_ALLOC => format!("CMP_SHIM_RESOURCE_EXHAUSTED({op}): OpenSSL memory allocation failed"),
        CMP_SHIM_ERR_OPENSSL_ENCODE => format!("CMP_SHIM_INTERNAL({op}): OpenSSL ASN.1 encoding failed"),
        _ => format!("CMP_SHIM_INTERNAL({op}): unknown error code={code}"),
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Convert raw OID bytes (from OPENSSL_malloc) to a String.
/// Bytes may not be null-terminated.
fn oid_bytes_to_string(ptr: *mut u8, len: c_int) -> String {
    if ptr.is_null() || len <= 0 {
        return String::new();
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    String::from_utf8_lossy(slice).to_string()
}

/// Convert allocated bytes to Vec<u8>, returns empty vec for NULL/zero-len.
fn ptr_bytes_to_vec(ptr: *mut u8, len: c_int) -> Vec<u8> {
    if ptr.is_null() || len <= 0 {
        return Vec::new();
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    slice.to_vec()
}
