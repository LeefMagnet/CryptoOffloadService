// 
// Create by kong on 2024/5/30
// Copyright 2024 Beijing Xinchangcheng Technology Development Co., Ltd.
//
#ifndef CYBERLIB_BUILD_MESSAGE_H
#define CYBERLIB_BUILD_MESSAGE_H

#include <string>

#define MIME_GETCA	     "application/x-x509-ca-cert"
// CA and RA Certificates Response
#define MIME_GETCA_RA	 "application/x-x509-ca-ra-cert"
// GetNextCACert Response
#define MIME_GETNEXT_CA  "application/x-x509-next-ca-cert"
// PKCSReq Response
#define MIME_PKI	     "application/x-pki-message"

namespace iwall {

class Message {
public:
    typedef enum {
        OPERATION_GETCA     = 1,
        OPERATION_ENROLL    = 3,
        OPERATION_GETCERT   = 5,
        OPERATION_GETCRL    = 7,
        OPERATION_GETNEXTCA = 15,
        OPERATION_GETCAPS   = 31
    } OperationType;

    typedef enum  {
        MESSAGE_NONE  = 0,
        MESSAGE_RENEWALREQ = 17,
        MESSAGE_PKCSREQ	= 19,
        MESSAGE_GETCERTINIT = 20,
        MESSAGE_GETCERT = 21,
        MESSAGE_GETCRL = 22
    } MessageType;
};
}

#endif //CYBERLIB_BUILD_MESSAGE_H
