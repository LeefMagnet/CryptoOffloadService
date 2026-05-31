// 
// Create by kong on 2024/5/29
// Copyright 2024 Beijing Xinchangcheng Technology Development Co., Ltd.
//

#include "content_info.h"
#include <cstring>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/pkcs7.h>

using namespace iwall;

struct CERTALIASORCN_st {
    int type;
    union {
        ASN1_UTF8STRING *alias;
        ASN1_UTF8STRING *commonName;
    } value;
};
typedef struct CERTALIASORCN_st CERT_INFORMATION;
ASN1_CHOICE(CERT_INFORMATION) = {
        ASN1_EXP(CERT_INFORMATION, value.alias, ASN1_UTF8STRING, 0),
        ASN1_EXP(CERT_INFORMATION, value.commonName, ASN1_UTF8STRING, 1)
} ASN1_CHOICE_END(CERT_INFORMATION)
IMPLEMENT_ASN1_FUNCTIONS(CERT_INFORMATION)

ContentInfo::ContentInfo(ContentInfo::ContentInfoType type) {
    type_ = type;
}

ContentInfo::~ContentInfo() = default;

std::vector<unsigned char> EncodeCertInformation(int type, const std::string& information) {
    std::vector<unsigned char> vData;
    unsigned char *buffer = nullptr;
    int buffer_len;
    CERT_INFORMATION *choice = CERT_INFORMATION_new();
    ASN1_UTF8STRING  *asn1Utf8String = ASN1_UTF8STRING_new();
    if (!choice || !asn1Utf8String) {
        goto cleanup;
    }
    choice->type = type;
    asn1Utf8String->data = static_cast<unsigned char*>(OPENSSL_zalloc(information.length() + 1));
    if (asn1Utf8String->data == nullptr)
    {
        goto cleanup;
    }
    if (asn1Utf8String->data) {
        memcpy(asn1Utf8String->data, information.data(), information.size());
    }
    asn1Utf8String->length = static_cast<int>(information.length());
    choice->value.alias = asn1Utf8String;
    buffer_len = i2d_CERT_INFORMATION(choice, &buffer);
    if (buffer_len > 0) {
        vData.assign(buffer, buffer + buffer_len);
    }
cleanup:
    CERT_INFORMATION_free(choice);
    OPENSSL_free(buffer);
    return vData;
}

std::vector<unsigned char>EncodeSerialNumber(const std::string& serialNumber) {
    std::vector<unsigned char> vData;
    int64_t pr = 0;
    unsigned char *buffer = nullptr;
    int buffer_len;
    BIGNUM *bn = BN_new();
    ASN1_INTEGER *ai = ASN1_INTEGER_new();
    PKCS7_ISSUER_AND_SERIAL *issuerAndSerial = PKCS7_ISSUER_AND_SERIAL_new();
    if (bn == nullptr || ai == nullptr || issuerAndSerial == nullptr) {
        goto cleanup;
    }
    BN_hex2bn(&bn, serialNumber.data());
    BN_to_ASN1_INTEGER(bn, ai);
    ASN1_INTEGER_get_int64(&pr, ai);
    ASN1_INTEGER_set(issuerAndSerial->serial, pr);
    buffer_len = i2d_PKCS7_ISSUER_AND_SERIAL(issuerAndSerial, &buffer);
    if (buffer_len > 0) {
        vData.assign(buffer, buffer + buffer_len);
    }
cleanup:
    OPENSSL_free(buffer);
    PKCS7_ISSUER_AND_SERIAL_free(issuerAndSerial);
    BN_free(bn);
    ASN1_INTEGER_free(ai);
    return vData;
}

std::vector<unsigned char> ContentInfo::EncodeData(const std::string &buffer) const
{
    std::vector<unsigned char> vData;
    switch (type_) {
        case Alias:
            vData = EncodeCertInformation(0, buffer);
            break;
        case CommonName:
            vData = EncodeCertInformation(1, buffer);
            break;
        case SerialNumber:
            vData = EncodeSerialNumber(buffer);
            break;
        default:
            break;
    }
    return vData;
}



