#include <openssl/asn1.h>
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

static int validate_complete_tlv(const unsigned char *der, int der_len, int expected_tag,
                                 int expected_class_bits) {
    long len = 0;
    int tag = 0;
    int xclass = 0;
    const unsigned char *p = der;
    int ret = ASN1_get_object(&p, &len, &tag, &xclass, der_len);
    if ((ret & 0x80) != 0) {
        return 0;
    }
    if ((ret & V_ASN1_CONSTRUCTED) == 0 && expected_tag == V_ASN1_SEQUENCE) {
        return 0;
    }
    if (expected_class_bits >= 0 && xclass != expected_class_bits) {
        return 0;
    }
    if (expected_tag >= 0 && tag != expected_tag) {
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

int cmp_shim_build_protected_part(const unsigned char *header_der, int header_der_len,
                                  const unsigned char *body_der, int body_der_len,
                                  unsigned char **out_der, int *out_der_len) {
    if (header_der == NULL || body_der == NULL || out_der == NULL || out_der_len == NULL) {
        return CMP_SHIM_ERR_NULL_ARG;
    }
    if (header_der_len <= 0 || body_der_len <= 0) {
        return CMP_SHIM_ERR_BAD_LENGTH;
    }
    if (!validate_complete_tlv(header_der, header_der_len, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL)) {
        return CMP_SHIM_ERR_HEADER_DER;
    }
    if (!validate_complete_tlv(body_der, body_der_len, -1, V_ASN1_CONTEXT_SPECIFIC)) {
        return CMP_SHIM_ERR_BODY_DER;
    }

    int content_len = header_der_len + body_der_len;
    int total = ASN1_object_size(1, content_len, V_ASN1_SEQUENCE);
    unsigned char *buf = OPENSSL_malloc((size_t)total);
    if (buf == NULL) {
        return CMP_SHIM_ERR_OPENSSL_ALLOC;
    }

    unsigned char *p = buf;
    ASN1_put_object(&p, 1, content_len, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    memcpy(p, header_der, (size_t)header_der_len);
    p += header_der_len;
    memcpy(p, body_der, (size_t)body_der_len);

    *out_der = buf;
    *out_der_len = total;
    return CMP_SHIM_OK;
}

int cmp_shim_build_pki_message(const unsigned char *header_der, int header_der_len,
                               const unsigned char *body_der, int body_der_len,
                               const char *protection_alg_oid,
                               const unsigned char *signature, int signature_len,
                               unsigned char **out_der, int *out_der_len) {
    unsigned char *alg_der = NULL;
    unsigned char *alg_exp = NULL;
    unsigned char *sig_der = NULL;
    unsigned char *sig_exp = NULL;
    int alg_der_len = 0, alg_exp_len = 0, sig_der_len = 0, sig_exp_len = 0;
    int ok = 0;

    if (header_der == NULL || body_der == NULL || protection_alg_oid == NULL ||
        signature == NULL || out_der == NULL || out_der_len == NULL) {
        return CMP_SHIM_ERR_NULL_ARG;
    }
    if (signature_len <= 0) {
        return CMP_SHIM_ERR_BAD_LENGTH;
    }
    if (!validate_complete_tlv(header_der, header_der_len, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL)) {
        return CMP_SHIM_ERR_HEADER_DER;
    }
    if (!validate_complete_tlv(body_der, body_der_len, -1, V_ASN1_CONTEXT_SPECIFIC)) {
        return CMP_SHIM_ERR_BODY_DER;
    }

    ASN1_OBJECT *obj = OBJ_txt2obj(protection_alg_oid, 1);
    if (obj == NULL) {
        ok = CMP_SHIM_ERR_OID_INVALID;
        goto end;
    }
    X509_ALGOR *alg = X509_ALGOR_new();
    if (alg == NULL) {
        ASN1_OBJECT_free(obj);
        ok = CMP_SHIM_ERR_OPENSSL_ALLOC;
        goto end;
    }
    int ptype = (strcmp(protection_alg_oid, "1.3.101.112") == 0 ||
                 strcmp(protection_alg_oid, "1.2.156.10197.1.501") == 0)
                    ? -1
                    : V_ASN1_NULL;
    X509_ALGOR_set0(alg, obj, ptype, NULL);
    alg_der_len = i2d_X509_ALGOR(alg, NULL);
    if (alg_der_len <= 0) {
        X509_ALGOR_free(alg);
        ok = CMP_SHIM_ERR_OPENSSL_ENCODE;
        goto end;
    }
    alg_der = OPENSSL_malloc((size_t)alg_der_len);
    if (alg_der == NULL) {
        X509_ALGOR_free(alg);
        ok = CMP_SHIM_ERR_OPENSSL_ALLOC;
        goto end;
    }
    unsigned char *ap = alg_der;
    if (i2d_X509_ALGOR(alg, &ap) != alg_der_len) {
        X509_ALGOR_free(alg);
        ok = CMP_SHIM_ERR_OPENSSL_ENCODE;
        goto end;
    }
    X509_ALGOR_free(alg);

    ASN1_BIT_STRING *bs = ASN1_BIT_STRING_new();
    if (bs == NULL) {
        ok = CMP_SHIM_ERR_OPENSSL_ALLOC;
        goto end;
    }
    if (ASN1_BIT_STRING_set(bs, (unsigned char *)signature, signature_len) != 1) {
        ASN1_BIT_STRING_free(bs);
        ok = CMP_SHIM_ERR_OPENSSL_ENCODE;
        goto end;
    }
    sig_der_len = i2d_ASN1_BIT_STRING(bs, NULL);
    if (sig_der_len <= 0) {
        ASN1_BIT_STRING_free(bs);
        ok = CMP_SHIM_ERR_OPENSSL_ENCODE;
        goto end;
    }
    sig_der = OPENSSL_malloc((size_t)sig_der_len);
    if (sig_der == NULL) {
        ASN1_BIT_STRING_free(bs);
        ok = CMP_SHIM_ERR_OPENSSL_ALLOC;
        goto end;
    }
    unsigned char *sp = sig_der;
    if (i2d_ASN1_BIT_STRING(bs, &sp) != sig_der_len) {
        ASN1_BIT_STRING_free(bs);
        ok = CMP_SHIM_ERR_OPENSSL_ENCODE;
        goto end;
    }
    ASN1_BIT_STRING_free(bs);

    if (!wrap_explicit(0, alg_der, alg_der_len, &alg_exp, &alg_exp_len)) {
        ok = CMP_SHIM_ERR_OPENSSL_ALLOC;
        goto end;
    }
    if (!wrap_explicit(1, sig_der, sig_der_len, &sig_exp, &sig_exp_len)) {
        ok = CMP_SHIM_ERR_OPENSSL_ALLOC;
        goto end;
    }

    int content_len = header_der_len + body_der_len + alg_exp_len + sig_exp_len;
    int total_len = ASN1_object_size(1, content_len, V_ASN1_SEQUENCE);
    unsigned char *out = OPENSSL_malloc((size_t)total_len);
    if (out == NULL) {
        ok = CMP_SHIM_ERR_OPENSSL_ALLOC;
        goto end;
    }
    unsigned char *p = out;
    ASN1_put_object(&p, 1, content_len, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    memcpy(p, header_der, (size_t)header_der_len);
    p += header_der_len;
    memcpy(p, body_der, (size_t)body_der_len);
    p += body_der_len;
    memcpy(p, alg_exp, (size_t)alg_exp_len);
    p += alg_exp_len;
    memcpy(p, sig_exp, (size_t)sig_exp_len);

    *out_der = out;
    *out_der_len = total_len;
    ok = CMP_SHIM_OK;

end:
    if (ok != CMP_SHIM_OK) {
        *out_der = NULL;
        *out_der_len = 0;
    }
    if (alg_der != NULL) OPENSSL_free(alg_der);
    if (alg_exp != NULL) OPENSSL_free(alg_exp);
    if (sig_der != NULL) OPENSSL_free(sig_der);
    if (sig_exp != NULL) OPENSSL_free(sig_exp);
    return ok == 0 ? CMP_SHIM_ERR_OPENSSL_ENCODE : ok;
}
