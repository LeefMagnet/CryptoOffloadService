/*
 * CMP PKIMessage shim — RFC 4210 / OpenSSL OSSL_CMP_MSG ASN.1 layout:
 *   PKIMessage ::= SEQUENCE { header, body, protection [0], extraCerts [1] }
 *   protectionAlg is inside PKIHeader [1], not at message level.
 */
#include <openssl/asn1.h>
#include <openssl/cmp.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <string.h>

#define CMP_SHIM_OK 1
#define CMP_SHIM_ERR_NULL_ARG -1
#define CMP_SHIM_ERR_BAD_LENGTH -2
#define CMP_SHIM_ERR_HEADER_DER -3
#define CMP_SHIM_ERR_BODY_DER -4
#define CMP_SHIM_ERR_OID_INVALID -5
#define CMP_SHIM_ERR_OPENSSL_ALLOC -6
#define CMP_SHIM_ERR_OPENSSL_ENCODE -7
#define CMP_SHIM_ERR_MSG_DER -8

/* Must match OpenSSL 3.x ossl_cmp_pkiheader_st (cmp_local.h). */
struct cmp_pkiheader_fields {
    ASN1_INTEGER *pvno;
    GENERAL_NAME *sender;
    GENERAL_NAME *recipient;
    ASN1_GENERALIZEDTIME *messageTime;
    X509_ALGOR *protectionAlg;
    ASN1_OCTET_STRING *senderKID;
    ASN1_OCTET_STRING *recipKID;
    ASN1_OCTET_STRING *transactionID;
    ASN1_OCTET_STRING *senderNonce;
    ASN1_OCTET_STRING *recipientNonce;
    void *freeText;
    void *generalInfo;
};

/* Must match OpenSSL 3.x ossl_cmp_msg_st fields used by i2d/d2i_OSSL_CMP_MSG. */
struct cmp_msg_fields {
    OSSL_CMP_PKIHEADER *header;
    void *body;
    ASN1_BIT_STRING *protection;
    void *extraCerts;
    void *libctx;
    char *propq;
};

static int validate_body_tlv(const unsigned char *der, int der_len) {
    long len = 0;
    int tag = 0;
    int xclass = 0;
    const unsigned char *p = der;
    int ret = ASN1_get_object(&p, &len, &tag, &xclass, der_len);
    if ((ret & 0x80) != 0) {
        return 0;
    }
    if (xclass != V_ASN1_CONTEXT_SPECIFIC) {
        return 0;
    }
    if ((p - der) + len != der_len) {
        return 0;
    }
    return 1;
}

static int wrap_explicit(int tag_no, const unsigned char *inner, int inner_len,
                         unsigned char **out_der, int *out_len) {
    int total = ASN1_object_size(1, inner_len, tag_no);
    unsigned char *buf = OPENSSL_malloc((size_t)total);
    if (buf == NULL) {
        return 0;
    }
    unsigned char *p = buf;
    ASN1_put_object(&p, 1, inner_len, tag_no, V_ASN1_CONTEXT_SPECIFIC);
    memcpy(p, inner, (size_t)inner_len);
    *out_der = buf;
    *out_len = total;
    return 1;
}

static OSSL_CMP_PKIHEADER *d2i_pkiheader(const unsigned char *der, int der_len) {
    const unsigned char *p = der;
    return d2i_OSSL_CMP_PKIHEADER(NULL, &p, der_len);
}

static int i2d_pkiheader_buf(OSSL_CMP_PKIHEADER *hdr, unsigned char **out, int *out_len) {
    int n = i2d_OSSL_CMP_PKIHEADER(hdr, NULL);
    if (n <= 0) {
        return 0;
    }
    unsigned char *buf = OPENSSL_malloc((size_t)n);
    if (buf == NULL) {
        return 0;
    }
    unsigned char *p = buf;
    if (i2d_OSSL_CMP_PKIHEADER(hdr, &p) != n) {
        OPENSSL_free(buf);
        return 0;
    }
    *out = buf;
    *out_len = n;
    return 1;
}

static X509_ALGOR *protection_alg_from_oid(const char *oid_str) {
    ASN1_OBJECT *obj = OBJ_txt2obj(oid_str, 1);
    if (obj == NULL) {
        return NULL;
    }
    X509_ALGOR *alg = X509_ALGOR_new();
    if (alg == NULL) {
        ASN1_OBJECT_free(obj);
        return NULL;
    }
    int ptype = (strcmp(oid_str, "1.3.101.112") == 0 || strcmp(oid_str, "1.2.156.10197.1.501") == 0)
                    ? -1
                    : V_ASN1_NULL;
    X509_ALGOR_set0(alg, obj, ptype, NULL);
    return alg;
}

/* Extract the second element (PKIBody TLV) from a PKIMessage DER. */
static int extract_pkibody_tlv(const unsigned char *msg_der, int msg_len, unsigned char **out,
                               int *out_len) {
    const unsigned char *p = msg_der;
    const unsigned char *end = msg_der + msg_len;
    long len = 0;
    int tag = 0;
    int xclass = 0;
    int ret;

    ret = ASN1_get_object(&p, &len, &tag, &xclass, end - p);
    if ((ret & 0x80) != 0 || tag != V_ASN1_SEQUENCE) {
        return 0;
    }
    const unsigned char *seq_end = p + len;

    ret = ASN1_get_object(&p, &len, &tag, &xclass, seq_end - p);
    if ((ret & 0x80) != 0) {
        return 0;
    }
    p += len; /* skip PKIHeader */

    const unsigned char *body_start = p;
    ret = ASN1_get_object(&p, &len, &tag, &xclass, seq_end - p);
    if ((ret & 0x80) != 0) {
        return 0;
    }
    p += len;
    int tlv_len = (int)(p - body_start);
    unsigned char *buf = OPENSSL_malloc((size_t)tlv_len);
    if (buf == NULL) {
        return 0;
    }
    memcpy(buf, body_start, (size_t)tlv_len);
    *out = buf;
    *out_len = tlv_len;
    return 1;
}

static int verify_pki_message_der(const unsigned char *der, int der_len) {
    const unsigned char *p = der;
    OSSL_CMP_MSG *msg = d2i_OSSL_CMP_MSG(NULL, &p, der_len);
    if (msg == NULL) {
        return 0;
    }
    OSSL_CMP_MSG_free(msg);
    return 1;
}

int cmp_shim_build_protected_part(const unsigned char *header_der, int header_der_len,
                                  const unsigned char *body_der, int body_der_len,
                                  unsigned char **out_der, int *out_der_len) {
    OSSL_CMP_PKIHEADER *hdr = NULL;
    unsigned char *hdr_buf = NULL;
    int hdr_len = 0;
    int ok = CMP_SHIM_OK;

    if (header_der == NULL || body_der == NULL || out_der == NULL || out_der_len == NULL) {
        return CMP_SHIM_ERR_NULL_ARG;
    }
    if (header_der_len <= 0 || body_der_len <= 0) {
        return CMP_SHIM_ERR_BAD_LENGTH;
    }
    if (!validate_body_tlv(body_der, body_der_len)) {
        return CMP_SHIM_ERR_BODY_DER;
    }

    hdr = d2i_pkiheader(header_der, header_der_len);
    if (hdr == NULL) {
        return CMP_SHIM_ERR_HEADER_DER;
    }
    if (!i2d_pkiheader_buf(hdr, &hdr_buf, &hdr_len)) {
        ok = CMP_SHIM_ERR_OPENSSL_ENCODE;
        goto end;
    }

    int content_len = hdr_len + body_der_len;
    int total = ASN1_object_size(1, content_len, V_ASN1_SEQUENCE);
    unsigned char *buf = OPENSSL_malloc((size_t)total);
    if (buf == NULL) {
        ok = CMP_SHIM_ERR_OPENSSL_ALLOC;
        goto end;
    }
    unsigned char *p = buf;
    ASN1_put_object(&p, 1, content_len, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    memcpy(p, hdr_buf, (size_t)hdr_len);
    p += hdr_len;
    memcpy(p, body_der, (size_t)body_der_len);

    *out_der = buf;
    *out_der_len = total;

end:
    if (hdr != NULL) {
        OSSL_CMP_PKIHEADER_free(hdr);
    }
    if (hdr_buf != NULL) {
        OPENSSL_free(hdr_buf);
    }
    if (ok != CMP_SHIM_OK) {
        *out_der = NULL;
        *out_der_len = 0;
    }
    return ok;
}

int cmp_shim_build_pki_message(const unsigned char *header_der, int header_der_len,
                               const unsigned char *body_der, int body_der_len,
                               const char *protection_alg_oid,
                               const unsigned char *signature, int signature_len,
                               unsigned char **out_der, int *out_der_len) {
    OSSL_CMP_PKIHEADER *hdr = NULL;
    struct cmp_pkiheader_fields *hf = NULL;
    unsigned char *enc_hdr = NULL;
    int enc_hdr_len = 0;
    unsigned char *sig_der = NULL;
    int sig_der_len = 0;
    unsigned char *prot_exp = NULL;
    int prot_exp_len = 0;
    X509_ALGOR *alg = NULL;
    ASN1_BIT_STRING *bs = NULL;
    int ok = CMP_SHIM_OK;

    if (header_der == NULL || body_der == NULL || protection_alg_oid == NULL ||
        signature == NULL || out_der == NULL || out_der_len == NULL) {
        return CMP_SHIM_ERR_NULL_ARG;
    }
    if (signature_len <= 0) {
        return CMP_SHIM_ERR_BAD_LENGTH;
    }
    if (!validate_body_tlv(body_der, body_der_len)) {
        return CMP_SHIM_ERR_BODY_DER;
    }

    hdr = d2i_pkiheader(header_der, header_der_len);
    if (hdr == NULL) {
        return CMP_SHIM_ERR_HEADER_DER;
    }

    alg = protection_alg_from_oid(protection_alg_oid);
    if (alg == NULL) {
        ok = CMP_SHIM_ERR_OID_INVALID;
        goto end;
    }
    hf = (struct cmp_pkiheader_fields *)hdr;
    X509_ALGOR_free(hf->protectionAlg);
    hf->protectionAlg = alg;
    alg = NULL;

    if (!i2d_pkiheader_buf(hdr, &enc_hdr, &enc_hdr_len)) {
        ok = CMP_SHIM_ERR_OPENSSL_ENCODE;
        goto end;
    }

    bs = ASN1_BIT_STRING_new();
    if (bs == NULL) {
        ok = CMP_SHIM_ERR_OPENSSL_ALLOC;
        goto end;
    }
    if (ASN1_BIT_STRING_set(bs, (unsigned char *)signature, signature_len) != 1) {
        ok = CMP_SHIM_ERR_OPENSSL_ENCODE;
        goto end;
    }
    sig_der_len = i2d_ASN1_BIT_STRING(bs, NULL);
    if (sig_der_len <= 0) {
        ok = CMP_SHIM_ERR_OPENSSL_ENCODE;
        goto end;
    }
    sig_der = OPENSSL_malloc((size_t)sig_der_len);
    if (sig_der == NULL) {
        ok = CMP_SHIM_ERR_OPENSSL_ALLOC;
        goto end;
    }
    unsigned char *sp = sig_der;
    if (i2d_ASN1_BIT_STRING(bs, &sp) != sig_der_len) {
        ok = CMP_SHIM_ERR_OPENSSL_ENCODE;
        goto end;
    }

    if (!wrap_explicit(0, sig_der, sig_der_len, &prot_exp, &prot_exp_len)) {
        ok = CMP_SHIM_ERR_OPENSSL_ALLOC;
        goto end;
    }

    int content_len = enc_hdr_len + body_der_len + prot_exp_len;
    int total_len = ASN1_object_size(1, content_len, V_ASN1_SEQUENCE);
    unsigned char *out = OPENSSL_malloc((size_t)total_len);
    if (out == NULL) {
        ok = CMP_SHIM_ERR_OPENSSL_ALLOC;
        goto end;
    }
    unsigned char *p = out;
    ASN1_put_object(&p, 1, content_len, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    memcpy(p, enc_hdr, (size_t)enc_hdr_len);
    p += enc_hdr_len;
    memcpy(p, body_der, (size_t)body_der_len);
    p += body_der_len;
    memcpy(p, prot_exp, (size_t)prot_exp_len);

    if (!verify_pki_message_der(out, total_len)) {
        OPENSSL_free(out);
        ok = CMP_SHIM_ERR_OPENSSL_ENCODE;
        goto end;
    }

    *out_der = out;
    *out_der_len = total_len;
    ok = CMP_SHIM_OK;

end:
    if (hdr != NULL) {
        OSSL_CMP_PKIHEADER_free(hdr);
    }
    if (alg != NULL) {
        X509_ALGOR_free(alg);
    }
    if (bs != NULL) {
        ASN1_BIT_STRING_free(bs);
    }
    if (enc_hdr != NULL) {
        OPENSSL_free(enc_hdr);
    }
    if (sig_der != NULL) {
        OPENSSL_free(sig_der);
    }
    if (prot_exp != NULL) {
        OPENSSL_free(prot_exp);
    }
    if (ok != CMP_SHIM_OK) {
        *out_der = NULL;
        *out_der_len = 0;
    }
    return ok;
}

int cmp_shim_split_pki_message(const unsigned char *msg_der, int msg_der_len,
                               unsigned char **header_der, int *header_der_len,
                               unsigned char **body_der, int *body_der_len) {
    const unsigned char *p = msg_der;
    OSSL_CMP_MSG *msg = NULL;
    struct cmp_msg_fields *mf = NULL;
    int ok = CMP_SHIM_OK;

    if (msg_der == NULL || header_der == NULL || header_der_len == NULL || body_der == NULL ||
        body_der_len == NULL) {
        return CMP_SHIM_ERR_NULL_ARG;
    }
    if (msg_der_len <= 0) {
        return CMP_SHIM_ERR_BAD_LENGTH;
    }

    msg = d2i_OSSL_CMP_MSG(NULL, &p, msg_der_len);
    if (msg == NULL) {
        return CMP_SHIM_ERR_MSG_DER;
    }
    mf = (struct cmp_msg_fields *)msg;
    if (mf->header == NULL) {
        ok = CMP_SHIM_ERR_MSG_DER;
        goto end;
    }
    if (!i2d_pkiheader_buf(mf->header, header_der, header_der_len)) {
        ok = CMP_SHIM_ERR_OPENSSL_ENCODE;
        goto end;
    }
    if (!extract_pkibody_tlv(msg_der, msg_der_len, body_der, body_der_len)) {
        ok = CMP_SHIM_ERR_MSG_DER;
        goto end;
    }

end:
    if (msg != NULL) {
        OSSL_CMP_MSG_free(msg);
    }
    if (ok != CMP_SHIM_OK) {
        if (*header_der != NULL) {
            OPENSSL_free(*header_der);
            *header_der = NULL;
        }
        if (*body_der != NULL) {
            OPENSSL_free(*body_der);
            *body_der = NULL;
        }
        *header_der_len = 0;
        *body_der_len = 0;
    }
    return ok;
}
