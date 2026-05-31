//! SCEP SignedAttributes 解析（对齐 docs/reference/scep/signed_attributes.*）。

use anyhow::{anyhow, Context, Result};
use foreign_types::ForeignType;
use openssl::nid::Nid;
use openssl::pkcs7::Pkcs7;
use openssl_sys as ffi;
use std::ffi::CString;
use std::sync::Once;

/// 解析结果（内部），映射到 protobuf `ScepSignedAttributes`。
#[derive(Debug, Default, Clone)]
pub struct ParsedScepAttributes {
    pub transaction_id: String,
    pub message_type: i32,
    pub pki_status: i32,
    pub fail_info: i32,
    pub fail_info_text: String,
    pub sender_nonce: Vec<u8>,
    pub recipient_nonce: Vec<u8>,
    pub signing_time_der: Vec<u8>,
    pub extension_req: Vec<u8>,
    pub proxy_auth: Vec<u8>,
}

const OID_MESSAGE_TYPE: &str = "2.16.840.1.113733.1.9.2";
const OID_PKI_STATUS: &str = "2.16.840.1.113733.1.9.3";
const OID_FAIL_INFO: &str = "2.16.840.1.113733.1.9.4";
const OID_SENDER_NONCE: &str = "2.16.840.1.113733.1.9.5";
const OID_RECIPIENT_NONCE: &str = "2.16.840.1.113733.1.9.6";
const OID_TRANSACTION_ID: &str = "2.16.840.1.113733.1.9.7";
const OID_EXTENSION_REQ: &str = "2.16.840.1.113733.1.9.8";
const OID_PROXY_AUTH: &str = "1.3.6.1.4.1.4263.5.5";
const OID_FAIL_INFO_TEXT_RFC: &str = "1.3.6.1.5.5.7.24.1";
const OID_FAIL_INFO_TEXT_LEGACY: &str = "1.3.6.1.5.5.7.24";

static EXT_OID_INIT: Once = Once::new();

pub fn init_ext_scep_oids() {
    EXT_OID_INIT.call_once(|| {
        crate::scep_certrep::init_scep_oids();
        for (oid, sn, ln) in [
            (OID_EXTENSION_REQ, "scepExtensionReq", "SCEP extensionReq"),
            (OID_PROXY_AUTH, "scepProxyAuth", "SCEP proxyAuth"),
            (OID_FAIL_INFO_TEXT_LEGACY, "scepFailInfoTextLegacy", "SCEP failInfoText legacy"),
        ] {
            register_oid(oid, sn, ln);
        }
    });
}

fn register_oid(oid: &str, sn: &str, ln: &str) {
    let (Ok(c_oid), Ok(c_sn), Ok(c_ln)) = (CString::new(oid), CString::new(sn), CString::new(ln)) else {
        return;
    };
    unsafe {
        ffi::init();
        let obj = ffi::OBJ_txt2obj(c_oid.as_ptr(), 1);
        if obj.is_null() {
            return;
        }
        let known = ffi::OBJ_obj2nid(obj) != Nid::UNDEF.as_raw();
        ffi::ASN1_OBJECT_free(obj);
        if !known {
            ffi::OBJ_create(c_oid.as_ptr(), c_sn.as_ptr(), c_ln.as_ptr());
        }
    }
}

pub fn parse_from_pkcs7_der(pkcs7_der: &[u8]) -> Result<ParsedScepAttributes> {
    init_ext_scep_oids();
    let pkcs7 = Pkcs7::from_der(pkcs7_der).context("invalid PKCS7 DER")?;
    parse_from_pkcs7(&pkcs7)
}

pub fn parse_from_pkcs7(pkcs7: &Pkcs7) -> Result<ParsedScepAttributes> {
    init_ext_scep_oids();
    unsafe {
        ffi::init();
        let mut attrs = ParsedScepAttributes::default();
        let p7 = pkcs7.as_ptr();
        let sign = (*p7).d.sign;
        if sign.is_null() {
            return Err(anyhow!("PKCS7 is not signedData"));
        }
        let sk = (*sign).signer_info;
        if sk.is_null() || ffi::OPENSSL_sk_num(sk as *mut _) <= 0 {
            return Err(anyhow!("PKCS7 has no signer info"));
        }
        let si = ffi::OPENSSL_sk_value(sk as *mut _, 0) as *mut ffi::PKCS7_SIGNER_INFO;
        let auth_attrs = (*si).auth_attr;
        if auth_attrs.is_null() {
            return Ok(attrs);
        }
        read_attr_printable(auth_attrs, OID_TRANSACTION_ID, &mut attrs.transaction_id)?;
        if let Some(v) = read_attr_printable_opt(auth_attrs, OID_MESSAGE_TYPE)? {
            attrs.message_type = v.parse().unwrap_or(0);
        }
        if let Some(v) = read_attr_printable_opt(auth_attrs, OID_PKI_STATUS)? {
            attrs.pki_status = v.parse().unwrap_or(-1);
        }
        if let Some(v) = read_attr_printable_opt(auth_attrs, OID_FAIL_INFO)? {
            attrs.fail_info = v.parse().unwrap_or(-1);
        }
        if let Ok(Some(v)) = read_attr_utf8_or_printable(auth_attrs, OID_FAIL_INFO_TEXT_RFC) {
            attrs.fail_info_text = v;
        } else if let Ok(Some(v)) = read_attr_utf8_or_printable(auth_attrs, OID_FAIL_INFO_TEXT_LEGACY) {
            attrs.fail_info_text = v;
        }
        if let Some(v) = read_attr_octet(auth_attrs, OID_SENDER_NONCE)? {
            attrs.sender_nonce = v;
        }
        if let Some(v) = read_attr_octet(auth_attrs, OID_RECIPIENT_NONCE)? {
            attrs.recipient_nonce = v;
        }
        if let Some(v) = read_attr_any(auth_attrs, Nid::PKCS9_SIGNINGTIME)? {
            attrs.signing_time_der = v;
        }
        if let Some(v) = read_attr_any(auth_attrs, OID_EXTENSION_REQ)? {
            attrs.extension_req = v;
        }
        if let Some(v) = read_attr_any(auth_attrs, OID_PROXY_AUTH)? {
            attrs.proxy_auth = v;
        }
        Ok(attrs)
    }
}

unsafe fn read_attr_printable(
    stack: *mut ffi::stack_st_X509_ATTRIBUTE,
    oid: &str,
    out: &mut String,
) -> Result<()> {
    if let Some(v) = read_attr_printable_opt(stack, oid)? {
        *out = v;
    }
    Ok(())
}

unsafe fn read_attr_printable_opt(
    stack: *mut ffi::stack_st_X509_ATTRIBUTE,
    oid: &str,
) -> Result<Option<String>> {
    let bytes = read_attr_any(stack, oid)?;
    Ok(bytes.map(|b| String::from_utf8_lossy(&b).into_owned()))
}

unsafe fn read_attr_utf8_or_printable(
    stack: *mut ffi::stack_st_X509_ATTRIBUTE,
    oid: &str,
) -> Result<Option<String>> {
    read_attr_printable_opt(stack, oid)
}

unsafe fn read_attr_octet(
    stack: *mut ffi::stack_st_X509_ATTRIBUTE,
    oid: &str,
) -> Result<Option<Vec<u8>>> {
    read_attr_any(stack, oid)
}

unsafe fn read_attr_any(
    stack: *mut ffi::stack_st_X509_ATTRIBUTE,
    oid_or_nid: impl AttrLookup,
) -> Result<Option<Vec<u8>>> {
    let nid = oid_or_nid.nid()?;
    if nid == Nid::UNDEF.as_raw() {
        return Ok(None);
    }
    let target = ffi::OBJ_nid2obj(nid);
    if target.is_null() {
        return Ok(None);
    }
    let num = ffi::OPENSSL_sk_num(stack as *mut _);
    for i in 0..num {
        let attr = ffi::OPENSSL_sk_value(stack as *mut _, i) as *mut ffi::X509_ATTRIBUTE;
        let obj = ffi::X509_ATTRIBUTE_get0_object(attr);
        if ffi::OBJ_cmp(obj, target) != 0 {
            continue;
        }
        let ty = ffi::X509_ATTRIBUTE_get0_type(attr, 0);
        if ty.is_null() {
            return Ok(None);
        }
        let asn1 = (*ty).value.asn1_string;
        if asn1.is_null() {
            return Ok(None);
        }
        let data = ffi::ASN1_STRING_get0_data(asn1);
        let len = ffi::ASN1_STRING_length(asn1);
        if data.is_null() || len < 0 {
            return Ok(None);
        }
        let slice = std::slice::from_raw_parts(data, len as usize);
        return Ok(Some(slice.to_vec()));
    }
    Ok(None)
}

trait AttrLookup {
    fn nid(self) -> Result<i32>;
}

impl AttrLookup for &str {
    fn nid(self) -> Result<i32> {
        init_ext_scep_oids();
        let c = CString::new(self).context("oid cstring")?;
        unsafe {
            let obj = ffi::OBJ_txt2obj(c.as_ptr(), 1);
            if obj.is_null() {
                return Ok(Nid::UNDEF.as_raw());
            }
            let nid = ffi::OBJ_obj2nid(obj);
            ffi::ASN1_OBJECT_free(obj);
            Ok(nid)
        }
    }
}

impl AttrLookup for Nid {
    fn nid(self) -> Result<i32> {
        Ok(self.as_raw())
    }
}

pub fn map_message_type_proto(wire: i32) -> i32 {
    match wire {
        3 => 3,
        19 => 19,
        20 => 20,
        21 => 21,
        22 => 22,
        _ => 0,
    }
}

pub fn map_pki_status_proto(wire: i32) -> i32 {
    match wire {
        0 => 1,
        2 => 2,
        3 => 3,
        _ => 0,
    }
}

pub fn map_fail_info_proto(wire: i32) -> i32 {
    match wire {
        0 => 1,
        1 => 2,
        2 => 3,
        3 => 4,
        4 => 5,
        5 => 6,
        _ => 0,
    }
}

pub fn parsed_to_proto(p: ParsedScepAttributes) -> crate::pb::ScepSignedAttributes {
    crate::pb::ScepSignedAttributes {
        transaction_id: p.transaction_id,
        message_type: map_message_type_proto(p.message_type),
        pki_status: map_pki_status_proto(p.pki_status),
        fail_info: map_fail_info_proto(p.fail_info),
        fail_info_text: p.fail_info_text,
        sender_nonce: p.sender_nonce,
        recipient_nonce: p.recipient_nonce,
        signing_time_der: p.signing_time_der,
        extension_req: p.extension_req,
        proxy_auth: p.proxy_auth,
    }
}
