// 
// Create by kong on 2024/5/29
// Copyright 2024 Beijing Xinchangcheng Technology Development Co., Ltd.
//

#include "signed_attributes.h"
#include "crypto/random.h"
#include "util/hex_utils.h"

using namespace iwall;

// Attribute
typedef struct scep_oid_st {
    int  attr_type;
    const char *oid_s;
    const char *descr;
    const char *long_descr;
    int  nid;
} SCEP_CONF_ATTRIBUTE;

typedef enum {
    SCEP_ATTRIBUTE_TYPE_UNKNOWN		 = -1,
    SCEP_ATTRIBUTE_MESSAGE_TYPE      = 0,
    SCEP_ATTRIBUTE_PKI_STATUS,
    SCEP_ATTRIBUTE_FAIL_INFO,
    SCEP_ATTRIBUTE_SENDER_NONCE,
    SCEP_ATTRIBUTE_RECIPIENT_NONCE,
    SCEP_ATTRIBUTE_TRANS_ID,
    SCEP_ATTRIBUTE_EXTENSION_REQ,
    SCEP_ATTRIBUTE_PROXY_AUTH,
    SCEP_ATTRIBUTE_FAIL_INFO_TEXT
} SCEP_ATTRIBUTE_TYPE;

SCEP_CONF_ATTRIBUTE SCEP_ATTRIBUTE_list [9] = {
        { SCEP_ATTRIBUTE_MESSAGE_TYPE, "2.16.840.1.113733.1.9.2",
                "scepMessageType", "SCEP Message Type", -1 },
        { SCEP_ATTRIBUTE_PKI_STATUS, "2.16.840.1.113733.1.9.3",
                "pkiStatus", "Status", -1 },
        { SCEP_ATTRIBUTE_FAIL_INFO, "2.16.840.1.113733.1.9.4",
                "failInfo", "Failure Info", -1 },
        { SCEP_ATTRIBUTE_SENDER_NONCE, "2.16.840.1.113733.1.9.5",
                "senderNonce", "Sender Nonce", -1 },
        { SCEP_ATTRIBUTE_RECIPIENT_NONCE, "2.16.840.1.113733.1.9.6",
                "recipientNonce", "Recipient Nonce", -1 },
        { SCEP_ATTRIBUTE_TRANS_ID, "2.16.840.1.113733.1.9.7",
                "transId", "Transaction Identifier", -1 },
        { SCEP_ATTRIBUTE_EXTENSION_REQ, "2.16.840.1.113733.1.9.8",
                "extensionReq", "Extension Request", -1 },
        { SCEP_ATTRIBUTE_PROXY_AUTH, "1.3.6.1.4.1.4263.5.5",
                "proxyAuth", "Proxy Authenticator", -1 },
        { SCEP_ATTRIBUTE_FAIL_INFO_TEXT, "1.3.6.1.5.5.7.24",
                "failInfoText", "Failure Info Text", -1 },
};


void InitializedAttributes() {
    int i = 0;
    int nid = NID_undef;
    SCEP_CONF_ATTRIBUTE *curr_oid;
    int len = (int)(sizeof(SCEP_ATTRIBUTE_list) / sizeof(SCEP_CONF_ATTRIBUTE));
    while( i < len ) {
        curr_oid = &SCEP_ATTRIBUTE_list[i];
        if (curr_oid->nid <= 0) {
            nid = OBJ_create(curr_oid->oid_s, curr_oid->descr,
                             curr_oid->long_descr);
            curr_oid->nid = nid;
        }
        i++;
    }
}

int SignedAttributesGetNid(SCEP_ATTRIBUTE_TYPE type) {
    SCEP_CONF_ATTRIBUTE *curr = nullptr;
    int i = 0;
    int len = (int)(sizeof(SCEP_ATTRIBUTE_list) / sizeof(SCEP_CONF_ATTRIBUTE));
    while( i < len ) {
        curr = &SCEP_ATTRIBUTE_list[i];
        if ( curr->attr_type == type )
            break;
        i++;
    }
    if ( curr ) return curr->nid;
    return NID_undef;
}

int AddAttributeString(STACK_OF(X509_ATTRIBUTE) *attrs, int nid,
                       const char *buffer, int len) {
    ASN1_STRING     *asn1_string;
    X509_ATTRIBUTE  *x509_a;
    if (!(asn1_string = ASN1_STRING_new())) {
        return (-1);
    }
    if (ASN1_STRING_set(asn1_string, buffer, len) <= 0) {
        return (-1);
    }
    x509_a = X509_ATTRIBUTE_create(nid, V_ASN1_PRINTABLESTRING,
                                   asn1_string);
    sk_X509_ATTRIBUTE_push(attrs, x509_a);
    return (0);
}

int AddAttributeOctet(STACK_OF(X509_ATTRIBUTE) *attrs, int nid,
                      const char *buffer, int len) {
    ASN1_STRING     *asn1_string;
    X509_ATTRIBUTE  *x509_a;
    if (!(asn1_string = ASN1_STRING_new())) {
        return (-1);
    }
    if (ASN1_STRING_set(asn1_string, buffer, len) <= 0) {
        return (-1);
    }
    x509_a = X509_ATTRIBUTE_create(nid, V_ASN1_OCTET_STRING,
                                   asn1_string);
    sk_X509_ATTRIBUTE_push(attrs, x509_a);
    return (0);
}

SignedAttributes::SignedAttributes() {
    if (attributes_ == nullptr) {
        attributes_ = sk_X509_ATTRIBUTE_new_null();
    }
    InitializedAttributes();
}

SignedAttributes::SignedAttributes(
        struct stack_st_X509_ATTRIBUTE *attributes) {
    attributes_ = sk_X509_ATTRIBUTE_dup(attributes);
}

SignedAttributes::~SignedAttributes() {
    if (attributes_ == nullptr) {
        return;
    }
    sk_X509_ATTRIBUTE_pop_free(attributes_,  X509_ATTRIBUTE_free);
};

SignedAttributes::SignedAttributes(SignedAttributes::MessageType messageType) {
    if (attributes_ == nullptr) {
        attributes_ = sk_X509_ATTRIBUTE_new_null();
    }
    InitializedAttributes();
    message_type_   = messageType;
    transaction_id_ = RandHexString(32);
    sender_nonce_   = RandHexString(16);
}

STACK_OF(X509_ATTRIBUTE) *SignedAttributes::EncodeAttributes() {
    if (attributes_ == nullptr) {
        return nullptr;
    }
    std::string message_type_str_ = std::to_string(message_type_);
    // messageType
    int nid_message_type = SignedAttributesGetNid(SCEP_ATTRIBUTE_MESSAGE_TYPE);
    AddAttributeString(attributes_,
                       nid_message_type,
                       message_type_str_.c_str(),
                       (int)message_type_str_.length());
    // transactionID
    int nid_trans_id = SignedAttributesGetNid(SCEP_ATTRIBUTE_TYPE::SCEP_ATTRIBUTE_TRANS_ID);
    AddAttributeString(attributes_,
                       nid_trans_id,
                       transaction_id_.c_str(),
                       (int)transaction_id_.length());
    // senderNonce
    int nid_sender_nonce = SignedAttributesGetNid(SCEP_ATTRIBUTE_TYPE::SCEP_ATTRIBUTE_SENDER_NONCE);
    AddAttributeOctet(attributes_,
                      nid_sender_nonce,
                      sender_nonce_.c_str(),
                      (int)sender_nonce_.length());
    return attributes_;
}

bool ParseSignedAttributeByNid(
        const STACK_OF(X509_ATTRIBUTE) *attribs,
        int target_nid,
        std::string *buffer) {
    if (buffer == nullptr) {
        return false;
    }
    int num = sk_X509_ATTRIBUTE_num(attribs);
    ASN1_OBJECT *targetObject = OBJ_nid2obj(target_nid);
    if (targetObject == nullptr) {
        return false;
    }
    for (int i = 0; i < num; ++i) {
        X509_ATTRIBUTE *attribute = sk_X509_ATTRIBUTE_value(attribs, i);
        if (attribute == nullptr)
            break;
        ASN1_OBJECT *srcObject = X509_ATTRIBUTE_get0_object(attribute);
        if (srcObject == nullptr)
            break;
        if (OBJ_cmp(srcObject, targetObject) == 0) {
            ASN1_TYPE *type = X509_ATTRIBUTE_get0_type(attribute, 0);
            if (type == nullptr)
                break;
            buffer->clear();
            buffer->assign((char *)type->value.asn1_string->data,
                           type->value.asn1_string->length);
        }
    }
    return true;
}

SignedAttributes::MessageType GetMessageType(
        const std::string& message_type_str) {
    if (message_type_str == "19") {
        return SignedAttributes::PKCSReq;
    } else if (message_type_str == "3") {
        return SignedAttributes::CertRep;
    } else if (message_type_str == "20") {
        return SignedAttributes::GetCertInitial;
    } else if (message_type_str == "21") {
        return SignedAttributes::GetCert;
    } else if (message_type_str == "22") {
        return SignedAttributes::GetCRL;
    }
    return SignedAttributes::UnKnown;
}

SignedAttributes::PKIStatus GetPkiStatus(
        const std::string& pki_status) {
    if (pki_status == "0") {
        return SignedAttributes::SUCCESS;
    } else if (pki_status == "2") {
        return SignedAttributes::FAILURE;
    } else if (pki_status == "3") {
        return SignedAttributes::PENDING;
    }
    return SignedAttributes::FAILURE;
}

SignedAttributes::FailInfo GetFailInfo(
        const std::string& fail_info) {
    if (fail_info == "0") {
        return SignedAttributes::BadAlg;
    } else if (fail_info == "1") {
        return SignedAttributes::BadMessageCheck;
    } else if (fail_info == "2") {
        return SignedAttributes::BadRequest;
    } else if (fail_info == "3") {
        return SignedAttributes::BadTime;
    } else if (fail_info == "4") {
        return SignedAttributes::BadCertId;
    }
    return SignedAttributes::BadUnKnown;
}

bool SignedAttributes::DecodeAttributes(
        const struct stack_st_X509_ATTRIBUTE *attributes) {
    std::string buffer;
    if (attributes == nullptr) {
        return false;
    }
    // Transaction id
    int nid_transaction_id = SignedAttributesGetNid(SCEP_ATTRIBUTE_TRANS_ID);
    buffer.clear();
    if (ParseSignedAttributeByNid(attributes, nid_transaction_id, &buffer)) {
        transaction_id_ = buffer;
    }
    // Message type
    int nid_message_type = SignedAttributesGetNid(SCEP_ATTRIBUTE_MESSAGE_TYPE);
    buffer.clear();
    if (ParseSignedAttributeByNid(attributes, nid_message_type, &buffer)) {
        message_type_ = GetMessageType(buffer);
    }
    // PKI Status
    int nid_pki_status = SignedAttributesGetNid(SCEP_ATTRIBUTE_PKI_STATUS);
    buffer.clear();
    if (ParseSignedAttributeByNid(attributes, nid_pki_status, &buffer)) {
        pki_status_ = GetPkiStatus(buffer);
    }
    // Fail Info
    int nid_fail_info = SignedAttributesGetNid(SCEP_ATTRIBUTE_FAIL_INFO);
    buffer.clear();
    if (ParseSignedAttributeByNid(attributes, nid_fail_info, &buffer)) {
        fail_info_ = GetFailInfo(buffer);
    }
    // Fail Info Text
    int nid_fail_info_txt = SignedAttributesGetNid(SCEP_ATTRIBUTE_FAIL_INFO_TEXT);
    buffer.clear();
    if (ParseSignedAttributeByNid(attributes, nid_fail_info_txt, &buffer)) {
        fail_info_txt_ = buffer;
    }
    // Sender Nonce
    int nid_sender_nonce = SignedAttributesGetNid(SCEP_ATTRIBUTE_SENDER_NONCE);
    buffer.clear();
    if (ParseSignedAttributeByNid(attributes, nid_sender_nonce, &buffer)) {
        sender_nonce_  = buffer;
    }
    // Recipient Nonce
    int nid_recipient_nonce = SignedAttributesGetNid(SCEP_ATTRIBUTE_RECIPIENT_NONCE);
    buffer.clear();
    if (ParseSignedAttributeByNid(attributes, nid_recipient_nonce, &buffer)) {
        recipient_nonce_  = buffer;
    }
    // Signing Time
    int nid_signing_time = NID_pkcs9_signingTime;
    buffer.clear();
    if (ParseSignedAttributeByNid(attributes, nid_signing_time, &buffer)) {
        signing_time_ = buffer;
    }
    return true;
}

void SignedAttributes::Print() const {
    fprintf(stdout, "Signed Attributes: \n");
    fprintf(stdout, "  - Transaction id:  %s\n", transaction_id_.c_str());
    fprintf(stdout, "  - Message type:    %d\n", message_type_);
    fprintf(stdout, "  - Pki status:      %d\n", pki_status_);
    fprintf(stdout, "  - Fail info:       %d\n", fail_info_);
    fprintf(stdout, "  - Fail info txt:   %s\n", fail_info_txt_.c_str());
    fprintf(stdout, "  - Sender nonce:    %s\n", HexUtils::EncodeStr(
            (unsigned char *) sender_nonce_.c_str(), sender_nonce_.length()).c_str());
    fprintf(stdout, "  - Recipient nonce: %s\n", HexUtils::EncodeStr(
            (unsigned char *) recipient_nonce_.c_str(), recipient_nonce_.length()).c_str());
    fprintf(stdout, "  - Signing Time :   %s\n", signing_time_.c_str());
}

std::string SignedAttributes::ToString() {
    std::string result("Attributes: ");
    result.append(" - Transaction id:");
    result.append(transaction_id_);
    result.append("/");
    result.append(" - Message type:");
    result.append(std::to_string(message_type_));
    result.append("/");
    result.append(" - Pki status:");
    result.append(std::to_string(pki_status_));
    result.append("/");
    result.append(" - Fail info:");
    result.append(std::to_string(fail_info_));
    result.append("/");
    result.append(" - Fail info txt:");
    result.append(fail_info_txt_);
    result.append("/");
    result.append(" - Sender nonce:");
    result.append(HexUtils::EncodeStr(
            (unsigned char *) sender_nonce_.c_str(), sender_nonce_.length()));
    result.append("/");
    result.append(" - Recipient nonce:");
    result.append(HexUtils::EncodeStr(
            (unsigned char *) recipient_nonce_.c_str(), recipient_nonce_.length()));
    result.append("/");
    result.append(" - Signing Time:");
    result.append(signing_time_);
    result.append("/");
    return result;
}
