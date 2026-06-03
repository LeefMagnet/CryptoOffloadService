use anyhow::{bail, Result};
use foreign_types::ForeignType;
use libloading::Library;
use openssl_sys as ffi;
use std::ffi::c_char;
use std::os::raw::{c_int, c_long, c_uchar, c_void};

use crate::crypto_sign;
use crate::key_store::{verifying_cert, KeyAccess};
use crate::pb::{HashAlgorithm, SignAlgorithm};

const CMP_SHIM_OK: c_int = 1;
const CMP_SHIM_ERR_NULL_ARG: c_int = -1;
const CMP_SHIM_ERR_BAD_LENGTH: c_int = -2;
const CMP_SHIM_ERR_HEADER_DER: c_int = -3;
const CMP_SHIM_ERR_BODY_DER: c_int = -4;
const CMP_SHIM_ERR_OID_INVALID: c_int = -5;
const CMP_SHIM_ERR_OPENSSL_ALLOC: c_int = -6;
const CMP_SHIM_ERR_OPENSSL_ENCODE: c_int = -7;

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

pub fn parse_pki_message(pki_message_der: &[u8]) -> Result<ParsedCmpMessage> {
    ensure_cmp_supported()?;
    let api = load_cmp_api()?;
    unsafe {
        let mut p = pki_message_der.as_ptr();
        let mut out: *mut OsslCmpMsg = std::ptr::null_mut();
        let msg = (api.d2i_cmp_msg)(&mut out, &mut p, pki_message_der.len() as c_long);
        if msg.is_null() {
            bail!("d2i_OSSL_CMP_MSG failed");
        }
        let body_type = (api.msg_get_bodytype)(msg);
        let hdr = (api.msg_get0_header)(msg);
        if hdr.is_null() {
            (api.cmp_msg_free)(msg);
            bail!("CMP parse failed: missing PKIHeader");
        }
        let pki_header_der = i2d_cmp_header(&api, hdr)?;
        let tx = asn1_octets((api.hdr_get0_transaction_id)(hdr));
        let recip = asn1_octets((api.hdr_get0_recip_nonce)(hdr));
        (api.cmp_msg_free)(msg);
        Ok(ParsedCmpMessage {
            body_type,
            protection_alg_oid: String::new(),
            protection: Vec::new(),
            protected_part_der: Vec::new(),
            pki_header_der,
            pki_body_der: Vec::new(),
            transaction_id: tx,
            sender_nonce: Vec::new(),
            recipient_nonce: recip,
        })
    }
}

pub fn verify_pki_message_protection(
    access: KeyAccess,
    pki_message_der: &[u8],
    _hash_algorithm: i32,
    _sign_algorithm: i32,
) -> Result<(bool, String, i32, i32)> {
    ensure_cmp_supported()?;
    let api = load_cmp_api()?;
    unsafe {
        let cert = match access {
            KeyAccess::Permanent(m) | KeyAccess::Temporary(m) => verifying_cert(&m)?,
        };
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
        Ok((
            ok,
            String::new(),
            HashAlgorithm::Unspecified as i32,
            SignAlgorithm::Unspecified as i32,
        ))
    }
}

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

pub fn ensure_cmp_supported() -> Result<()> {
    let _ = load_cmp_api()?;
    Ok(())
}

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

fn protection_alg_oid_for(sign_algorithm: i32, hash_algorithm: i32) -> Result<String> {
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

#[link(name = "cmp_shim", kind = "static")]
unsafe extern "C" {
    #[link_name = "cmp_shim_build_protected_part"]
    fn cmp_shim_build_protected_part_raw(
        header_der: *const u8,
        header_der_len: c_int,
        body_der: *const u8,
        body_der_len: c_int,
        out_der: *mut *mut u8,
        out_der_len: *mut c_int,
    ) -> c_int;

    #[link_name = "cmp_shim_build_pki_message"]
    fn cmp_shim_build_pki_message_raw(
        header_der: *const u8,
        header_der_len: c_int,
        body_der: *const u8,
        body_der_len: c_int,
        protection_alg_oid: *const c_char,
        signature: *const u8,
        signature_len: c_int,
        out_der: *mut *mut u8,
        out_der_len: *mut c_int,
    ) -> c_int;
}

fn cmp_shim_build_protected_part(header: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: c_int = 0;
        let code = cmp_shim_build_protected_part_raw(
            header.as_ptr(),
            header.len() as c_int,
            body.as_ptr(),
            body.len() as c_int,
            &mut out,
            &mut out_len,
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
    header: &[u8],
    body: &[u8],
    oid: &str,
    signature: &[u8],
) -> Result<Vec<u8>> {
    let c_oid = std::ffi::CString::new(oid).map_err(|_| anyhow::anyhow!("invalid oid"))?;
    unsafe {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: c_int = 0;
        let code = cmp_shim_build_pki_message_raw(
            header.as_ptr(),
            header.len() as c_int,
            body.as_ptr(),
            body.len() as c_int,
            c_oid.as_ptr(),
            signature.as_ptr(),
            signature.len() as c_int,
            &mut out,
            &mut out_len,
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

fn map_cmp_shim_error(op: &str, code: c_int) -> String {
    match code {
        CMP_SHIM_ERR_NULL_ARG => {
            format!("CMP_SHIM_INVALID_ARGUMENT({op}): null pointer input")
        }
        CMP_SHIM_ERR_BAD_LENGTH => {
            format!("CMP_SHIM_INVALID_ARGUMENT({op}): invalid DER/signature length")
        }
        CMP_SHIM_ERR_HEADER_DER => {
            format!("CMP_SHIM_INVALID_ARGUMENT({op}): pki_header_der must be DER SEQUENCE")
        }
        CMP_SHIM_ERR_BODY_DER => {
            format!("CMP_SHIM_INVALID_ARGUMENT({op}): pki_body_der must be context-specific DER")
        }
        CMP_SHIM_ERR_OID_INVALID => {
            format!("CMP_SHIM_INVALID_ARGUMENT({op}): invalid protection algorithm oid")
        }
        CMP_SHIM_ERR_OPENSSL_ALLOC => {
            format!("CMP_SHIM_RESOURCE_EXHAUSTED({op}): OpenSSL memory allocation failed")
        }
        CMP_SHIM_ERR_OPENSSL_ENCODE => {
            format!("CMP_SHIM_INTERNAL({op}): OpenSSL ASN.1 encoding failed")
        }
        _ => format!("CMP_SHIM_INTERNAL({op}): unknown error code={code}"),
    }
}

unsafe fn i2d_cmp_header(api: &CmpApi, hdr: *mut OsslCmpPkiHeader) -> Result<Vec<u8>> {
    let mut p: *mut c_uchar = std::ptr::null_mut();
    let n = (api.i2d_cmp_pkiheader)(hdr, &mut p);
    if n <= 0 || p.is_null() {
        bail!("i2d_OSSL_CMP_PKIHEADER failed");
    }
    let out = std::slice::from_raw_parts(p as *const u8, n as usize).to_vec();
    ffi::OPENSSL_free(p as *mut c_void);
    Ok(out)
}

unsafe fn asn1_octets(ptr: *mut ffi::ASN1_OCTET_STRING) -> Vec<u8> {
    if ptr.is_null() {
        return Vec::new();
    }
    let n = ffi::ASN1_STRING_length(ptr as *const ffi::ASN1_STRING);
    if n <= 0 {
        return Vec::new();
    }
    let p = ffi::ASN1_STRING_get0_data(ptr as *const ffi::ASN1_STRING);
    if p.is_null() {
        return Vec::new();
    }
    std::slice::from_raw_parts(p, n as usize).to_vec()
}
