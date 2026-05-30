//! RFC 8894 CertRep：FAILURE（pkiStatus=2）与 SUCCESS（pkiStatus=0，带 pkcsPKIEnvelope）。

use anyhow::{anyhow, Context, Result};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::{PKeyRef, Private};
use openssl::rand::rand_bytes;
use openssl::stack::Stack;
use openssl::symm::Cipher;
use openssl::x509::{X509, X509Ref};
use openssl_sys as ffi;
use std::ffi::CString;
use std::os::raw::c_int;
use std::ptr;
use std::sync::Once;

/// VeriSign SCEP 属性 OID（与多数 Go/Java SCEP 栈一致）
const OID_MESSAGE_TYPE: &str = "2.16.840.1.113733.1.9.2";
const OID_PKI_STATUS: &str = "2.16.840.1.113733.1.9.3";
const OID_FAIL_INFO: &str = "2.16.840.1.113733.1.9.4";
const OID_SENDER_NONCE: &str = "2.16.840.1.113733.1.9.5";
const OID_RECIPIENT_NONCE: &str = "2.16.840.1.113733.1.9.6";
const OID_TRANSACTION_ID: &str = "2.16.840.1.113733.1.9.7";
/// RFC 8894 `id-scep-failInfoText`（1.3.6.1.5.5.7.24.1）
const OID_FAIL_INFO_TEXT: &str = "1.3.6.1.5.5.7.24.1";

const MSG_TYPE_CERT_REP: &str = "3";
const PKI_STATUS_SUCCESS: &str = "0";
const PKI_STATUS_FAILURE: &str = "2";

/// SUCCESS CertRep 参数（与 Go `BuildSuccessRep` / smallstep `ParsePKIMessage` 对齐）
#[derive(Clone, Copy)]
pub struct ScepSuccessParams<'a> {
    pub transaction_id: &'a str,
    /// 请求 senderNonce → 响应 recipientNonce
    pub recipient_nonce: &'a [u8],
    /// 响应 senderNonce；为空则自动生成 16 字节
    pub sender_nonce: &'a [u8],
    pub issued_cert: &'a X509Ref,
    pub wrapper_cert: &'a X509Ref,
    /// SCEP CA（RSA），与 Go `rsaEncryptRecipients` 一致：Ed25519 wrapper 时加密给 CA
    pub ca_cert: &'a X509Ref,
}

/// failInfo 取值见 RFC 8894 Table 5（0..=4）
#[derive(Debug, Clone, Copy)]
pub struct ScepFailureParams<'a> {
    pub transaction_id: &'a str,
    /// 请求中的 senderNonce，写入响应的 recipientNonce
    pub recipient_nonce: &'a [u8],
    /// 响应 senderNonce；为空则自动生成 16 字节
    pub sender_nonce: &'a [u8],
    /// 0=badAlg, 1=badMessageCheck, 2=badRequest, 3=badTime, 4=badCertId
    pub fail_info: u8,
    pub fail_info_text: &'a str,
}

pub fn build_success_certrep(
    ca_cert: &X509Ref,
    ca_key: &PKeyRef<Private>,
    params: ScepSuccessParams<'_>,
) -> Result<Vec<u8>> {
    if params.transaction_id.is_empty() {
        return Err(anyhow!("transaction_id must not be empty"));
    }
    if params.recipient_nonce.is_empty() {
        return Err(anyhow!("recipient_nonce must not be empty"));
    }

    let mut sender_nonce_buf = [0u8; 16];
    let sender_nonce = if params.sender_nonce.is_empty() {
        rand_bytes(&mut sender_nonce_buf).context("failed to generate sender nonce")?;
        sender_nonce_buf.as_slice()
    } else {
        params.sender_nonce
    };

    let degenerate_der = build_degenerate_certificate_der(params.issued_cert)?;
    let enveloped_der =
        encrypt_envelope(params.wrapper_cert, params.ca_cert, &degenerate_der)?;

    unsafe {
        ffi::init();

        let p7 = cvt_p(ffi::PKCS7_new()).context("PKCS7_new")?;
        let p7 = Pkcs7::from_ptr(p7);

        cvt(ffi::PKCS7_set_type(
            p7.as_ptr(),
            Nid::PKCS7_SIGNED.as_raw(),
        ))
        .context("PKCS7_set_type")?;

        cvt(ffi::PKCS7_add_certificate(p7.as_ptr(), ca_cert.as_ptr()))
            .context("PKCS7_add_certificate")?;

        let si = ffi::PKCS7_add_signature(
            p7.as_ptr(),
            ca_cert.as_ptr(),
            ca_key.as_ptr(),
            MessageDigest::sha256().as_ptr(),
        );
        if si.is_null() {
            return Err(anyhow!("PKCS7_add_signature returned null"));
        }

        add_printable_attr(si, OID_MESSAGE_TYPE, MSG_TYPE_CERT_REP)?;
        add_printable_attr(si, OID_PKI_STATUS, PKI_STATUS_SUCCESS)?;
        add_printable_attr(si, OID_TRANSACTION_ID, params.transaction_id)?;
        add_octet_attr(si, OID_SENDER_NONCE, sender_nonce)?;
        add_octet_attr(si, OID_RECIPIENT_NONCE, params.recipient_nonce)?;

        cvt(ffi::PKCS7_content_new(p7.as_ptr(), Nid::PKCS7_DATA.as_raw()))
            .context("PKCS7_content_new")?;

        // dataInit → BIO_write → dataFinal；dataFinal 不释放 chain，须 BIO_free_all（否则每请求泄漏）。
        pkcs7_finalize_content(p7.as_ptr(), Some(&enveloped_der))
            .context("attach enveloped content to CertRep")?;

        p7.to_der().context("encode success CertRep DER")
    }
}

/// degenerate SignedData（仅证书、空 Data），与 smallstep `DegenerateCertificates` 一致。
fn build_degenerate_certificate_der(cert: &X509Ref) -> Result<Vec<u8>> {
    unsafe {
        ffi::init();
        let p7 = cvt_p(ffi::PKCS7_new()).context("PKCS7_new")?;
        let p7 = Pkcs7::from_ptr(p7);
        cvt(ffi::PKCS7_set_type(
            p7.as_ptr(),
            Nid::PKCS7_SIGNED.as_raw(),
        ))
        .context("PKCS7_set_type")?;
        cvt(ffi::PKCS7_add_certificate(p7.as_ptr(), cert.as_ptr()))
            .context("PKCS7_add_certificate")?;
        cvt(ffi::PKCS7_content_new(p7.as_ptr(), Nid::PKCS7_DATA.as_raw()))
            .context("PKCS7_content_new")?;
        pkcs7_finalize_content(p7.as_ptr(), None).context("finalize degenerate PKCS7")?;
        p7.to_der().context("encode degenerate cert PKCS7")
    }
}

/// 与 Go `rsaEncryptRecipients(p.P7.Certificates)` 对齐：仅 RSA；Ed25519 wrapper 时用 CA。
fn rsa_encrypt_recipient_stack(wrapper: &X509Ref, ca_cert: &X509Ref) -> Result<Stack<X509>> {
    let mut recipients = Stack::new().context("recipients stack")?;
    let mut n = 0usize;
    for cert in [wrapper, ca_cert] {
        if !cert
            .public_key()
            .map(|k| k.rsa().is_ok())
            .unwrap_or(false)
        {
            continue;
        }
        let owned =
            X509::from_der(&cert.to_der().context("encode cert for recipient stack")?)
                .context("clone RSA recipient cert")?;
        recipients.push(owned).context("push RSA recipient")?;
        n += 1;
    }
    if n == 0 {
        return Err(anyhow!("no RSA recipient for CertRep envelope"));
    }
    Ok(recipients)
}

fn encrypt_envelope(wrapper: &X509Ref, ca_cert: &X509Ref, plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipients = rsa_encrypt_recipient_stack(wrapper, ca_cert)?;
    let enveloped = Pkcs7::encrypt(
        &recipients,
        plaintext,
        Cipher::des_ede3_cbc(),
        Pkcs7Flags::BINARY,
    )
    .context("PKCS7 encrypt degenerate cert")?;
    enveloped.to_der().context("encode enveloped PKCS7")
}

pub fn build_failure_certrep(
    ca_cert: &X509Ref,
    ca_key: &PKeyRef<Private>,
    params: ScepFailureParams<'_>,
) -> Result<Vec<u8>> {
    if params.transaction_id.is_empty() {
        return Err(anyhow!("transaction_id must not be empty"));
    }
    if params.recipient_nonce.is_empty() {
        return Err(anyhow!("recipient_nonce must not be empty"));
    }
    if params.fail_info > 4 {
        return Err(anyhow!("fail_info must be 0..=4 per RFC 8894"));
    }
    if params.fail_info_text.is_empty() {
        return Err(anyhow!("fail_info_text must not be empty"));
    }

    let mut sender_nonce_buf = [0u8; 16];
    let sender_nonce = if params.sender_nonce.is_empty() {
        rand_bytes(&mut sender_nonce_buf).context("failed to generate sender nonce")?;
        sender_nonce_buf.as_slice()
    } else {
        params.sender_nonce
    };

    let fail_info_str = params.fail_info.to_string();

    unsafe {
        ffi::init();

        let p7 = cvt_p(ffi::PKCS7_new()).context("PKCS7_new")?;
        let p7 = Pkcs7::from_ptr(p7);

        cvt(ffi::PKCS7_set_type(
            p7.as_ptr(),
            Nid::PKCS7_SIGNED.as_raw(),
        ))
        .context("PKCS7_set_type")?;

        cvt(ffi::PKCS7_add_certificate(p7.as_ptr(), ca_cert.as_ptr()))
            .context("PKCS7_add_certificate")?;

        let si = ffi::PKCS7_add_signature(
            p7.as_ptr(),
            ca_cert.as_ptr(),
            ca_key.as_ptr(),
            MessageDigest::sha256().as_ptr(),
        );
        if si.is_null() {
            return Err(anyhow!("PKCS7_add_signature returned null"));
        }

        add_printable_attr(si, OID_MESSAGE_TYPE, MSG_TYPE_CERT_REP)?;
        add_printable_attr(si, OID_PKI_STATUS, PKI_STATUS_FAILURE)?;
        add_printable_attr(si, OID_FAIL_INFO, &fail_info_str)?;
        add_printable_attr(si, OID_TRANSACTION_ID, params.transaction_id)?;
        add_octet_attr(si, OID_SENDER_NONCE, sender_nonce)?;
        add_octet_attr(si, OID_RECIPIENT_NONCE, params.recipient_nonce)?;
        add_utf8_attr(si, OID_FAIL_INFO_TEXT, params.fail_info_text)?;

        cvt(ffi::PKCS7_content_new(p7.as_ptr(), Nid::PKCS7_DATA.as_raw()))
            .context("PKCS7_content_new")?;

        pkcs7_finalize_content(p7.as_ptr(), None).context("finalize failure CertRep")?;

        p7.to_der().context("encode failure CertRep DER")
    }
}

/// PKCS7_dataInit 返回的 BIO 链在 PKCS7_dataFinal 之后**不会**自动释放，必须 BIO_free_all。
unsafe fn pkcs7_finalize_content(p7: *mut ffi::PKCS7, content: Option<&[u8]>) -> Result<()> {
    let bio = cvt_p(ffi::PKCS7_dataInit(p7, ptr::null_mut())).context("PKCS7_dataInit")?;
    let mut err = None;
    if let Some(data) = content {
        let want = i32::try_from(data.len()).unwrap_or(i32::MAX);
        match cvt(ffi::BIO_write(
            bio,
            data.as_ptr() as *const _,
            want,
        )) {
            Ok(wrote) if wrote == want => {}
            Ok(wrote) => {
                err = Some(anyhow!("BIO_write: wrote {wrote} bytes, expected {want}"));
            }
            Err(e) => err = Some(e),
        }
    }
    if err.is_none() {
        if let Err(e) = cvt(ffi::PKCS7_dataFinal(p7, bio)).context("PKCS7_dataFinal") {
            err = Some(e);
        }
    }
    ffi::BIO_free_all(bio);
    match err {
        None => Ok(()),
        Some(e) => Err(e),
    }
}

fn cvt(r: c_int) -> Result<c_int> {
    if r <= 0 {
        Err(ErrorStack::get().into())
    } else {
        Ok(r)
    }
}

fn cvt_p<T>(r: *mut T) -> Result<*mut T> {
    if r.is_null() {
        Err(ErrorStack::get().into())
    } else {
        Ok(r)
    }
}

/// 进程启动时注册 SCEP 专有 OID（幂等）；CertRep 构建前也会自动调用。
pub fn init_scep_oids() {
    ensure_scep_oids_registered();
}

/// VeriSign/SCEP 专有属性 OID 不在 OpenSSL 内置 OBJ 表中（OBJ_obj2nid 返回 NID_undef）。
/// 启动时用 OBJ_create 注册为动态 NID（一次性、幂等），否则 PKCS7_add_signed_attribute 会失败。
static SCEP_OID_INIT: Once = Once::new();

fn ensure_scep_oids_registered() {
    SCEP_OID_INIT.call_once(|| {
        // (oid, short_name, long_name) — short_name 必须唯一
        let oids: [(&str, &str, &str); 7] = [
            (OID_MESSAGE_TYPE, "scepMessageType", "SCEP messageType"),
            (OID_PKI_STATUS, "scepPkiStatus", "SCEP pkiStatus"),
            (OID_FAIL_INFO, "scepFailInfo", "SCEP failInfo"),
            (OID_SENDER_NONCE, "scepSenderNonce", "SCEP senderNonce"),
            (OID_RECIPIENT_NONCE, "scepRecipientNonce", "SCEP recipientNonce"),
            (OID_TRANSACTION_ID, "scepTransactionID", "SCEP transactionID"),
            (OID_FAIL_INFO_TEXT, "scepFailInfoText", "SCEP failInfoText"),
        ];
        for (oid, sn, ln) in oids {
            let (c_oid, c_sn, c_ln) = match (
                CString::new(oid),
                CString::new(sn),
                CString::new(ln),
            ) {
                (Ok(o), Ok(s), Ok(l)) => (o, s, l),
                _ => continue,
            };
            unsafe {
                // 已知 OID（如标准库已收录）则跳过，避免重复创建
                let obj = ffi::OBJ_txt2obj(c_oid.as_ptr(), 1);
                let already = if obj.is_null() {
                    false
                } else {
                    let known = ffi::OBJ_obj2nid(obj) != Nid::UNDEF.as_raw();
                    ffi::ASN1_OBJECT_free(obj);
                    known
                };
                if !already {
                    ffi::OBJ_create(c_oid.as_ptr(), c_sn.as_ptr(), c_ln.as_ptr());
                }
            }
        }
    });
}

fn oid_nid(oid: &str) -> Result<c_int> {
    ensure_scep_oids_registered();
    let c = CString::new(oid).with_context(|| format!("invalid oid string: {oid}"))?;
    unsafe {
        let obj = ffi::OBJ_txt2obj(c.as_ptr(), 1);
        if obj.is_null() {
            return Err(anyhow!("OBJ_txt2obj failed for {oid}"));
        }
        let nid = ffi::OBJ_obj2nid(obj);
        ffi::ASN1_OBJECT_free(obj);
        if nid == Nid::UNDEF.as_raw() {
            return Err(anyhow!("unknown OID: {oid}"));
        }
        Ok(nid)
    }
}

fn add_printable_attr(si: *mut ffi::PKCS7_SIGNER_INFO, oid: &str, value: &str) -> Result<()> {
    let nid = oid_nid(oid)?;
    // PKCS7_add_signed_attribute 经 X509_ATTRIBUTE_create/ASN1_TYPE_set 接管传入指针，且按对应
    // ASN1 类型解读它。因此必须传一个真正的 ASN1_STRING（PrintableString）并转移所有权，
    // 不能传裸 CString 后又 drop —— 否则 OpenSSL 会把已释放内存当 ASN1_STRING 读，导致段错误。
    unsafe {
        let s = cvt_p(ffi::ASN1_STRING_type_new(ffi::V_ASN1_PRINTABLESTRING))
            .with_context(|| format!("ASN1_STRING_type_new {oid}"))?;
        if let Err(e) = cvt(ffi::ASN1_STRING_set(
            s,
            value.as_ptr() as *const _,
            value.len().try_into().unwrap_or(i32::MAX),
        ))
        .with_context(|| format!("ASN1_STRING_set {oid}"))
        {
            ffi::ASN1_STRING_free(s);
            return Err(e);
        }
        if let Err(e) = cvt(ffi::PKCS7_add_signed_attribute(
            si,
            nid,
            ffi::V_ASN1_PRINTABLESTRING,
            s as *mut _,
        ))
        .with_context(|| format!("PKCS7_add_signed_attribute {oid}"))
        {
            // 失败时尚未转移所有权，释放避免泄漏。
            ffi::ASN1_STRING_free(s);
            return Err(e);
        }
    }
    Ok(())
}

fn add_octet_attr(si: *mut ffi::PKCS7_SIGNER_INFO, oid: &str, value: &[u8]) -> Result<()> {
    let nid = oid_nid(oid)?;
    unsafe {
        let octet = cvt_p(ffi::ASN1_OCTET_STRING_new()).with_context(|| format!("octet attr {oid}"))?;
        if let Err(e) = cvt(ffi::ASN1_OCTET_STRING_set(
            octet,
            value.as_ptr() as *const _,
            value.len().try_into().unwrap_or(i32::MAX),
        ))
        .with_context(|| format!("ASN1_OCTET_STRING_set {oid}"))
        {
            ffi::ASN1_OCTET_STRING_free(octet);
            return Err(e);
        }
        if let Err(e) = cvt(ffi::PKCS7_add_signed_attribute(
            si,
            nid,
            ffi::V_ASN1_OCTET_STRING,
            octet as *mut _,
        ))
        .with_context(|| format!("PKCS7_add_signed_attribute {oid}"))
        {
            ffi::ASN1_OCTET_STRING_free(octet);
            return Err(e);
        }
        // 所有权已交给 SignedData 属性，勿再 ASN1_OCTET_STRING_free(octet)
    }
    Ok(())
}

fn add_utf8_attr(si: *mut ffi::PKCS7_SIGNER_INFO, oid: &str, value: &str) -> Result<()> {
    let nid = oid_nid(oid)?;
    unsafe {
        let s = cvt_p(ffi::ASN1_STRING_type_new(ffi::V_ASN1_UTF8STRING))
            .with_context(|| format!("ASN1_STRING_type_new {oid}"))?;
        if let Err(e) = cvt(ffi::ASN1_STRING_set(
            s,
            value.as_ptr() as *const _,
            value.len().try_into().unwrap_or(i32::MAX),
        ))
        .with_context(|| format!("ASN1_STRING_set {oid}"))
        {
            ffi::ASN1_STRING_free(s);
            return Err(e);
        }
        if let Err(e) = cvt(ffi::PKCS7_add_signed_attribute(
            si,
            nid,
            ffi::V_ASN1_UTF8STRING,
            s as *mut _,
        ))
        .with_context(|| format!("PKCS7_add_signed_attribute {oid}"))
        {
            ffi::ASN1_STRING_free(s);
            return Err(e);
        }
    }
    Ok(())
}
