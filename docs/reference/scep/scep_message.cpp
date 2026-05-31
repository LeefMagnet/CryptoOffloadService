// 
// Create by kong on 2024/7/15
// Copyright 2024 Beijing Xinchangcheng Technology Development Co., Ltd.
//

#include "scep_message.h"

using namespace iwall;

#define SCEP_MIME_GETCA	     "application/x-x509-ca-cert"
// CA and RA Certificates Response
#define SCEP_MIME_GETCA_RA	 "application/x-x509-ca-ra-cert"
// GetNextCACert Response
#define SCEP_MIME_GETNEXT_CA "application/x-x509-next-ca-cert"
// PKCSReq Response
#define SCEP_MIME_PKI	     "application/x-pki-message"

std::string ScepMessage::GetScepMime(
        ScepMessage::OperationType operation) {
    std::string sMime;
    switch (operation) {
        case OPERATION_GETCA:
            sMime = SCEP_MIME_GETCA;
            break;
        case OPERATION_GETCARA:
            sMime = SCEP_MIME_GETCA_RA;
            break;
        case OPERATION_ENROLL:
        case OPERATION_GETCERT:
        case OPERATION_GETCRL:
            sMime = SCEP_MIME_PKI;
            break;
        case OPERATION_GETNEXTCA:
            sMime = SCEP_MIME_GETNEXT_CA;
            break;
        default:
            break;
    }
    return sMime;
}
