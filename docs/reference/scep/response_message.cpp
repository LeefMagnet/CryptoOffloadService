//
// Create by kong on 2024/5/30
// Copyright 2024 Beijing Xinchangcheng Technology Development Co., Ltd.
//

#include "response_message.h"

using namespace iwall;

bool ResponseMessage::VerifyContentType(Message::OperationType operationType,
                                        const std::string &sMime) {
    bool res = false;
    switch (operationType) {
        case OPERATION_GETCA:
            res = ((sMime.find(MIME_GETCA) != std::string::npos) ||
                   (sMime.find(MIME_GETCA_RA) != std::string::npos));
            break;
        case OPERATION_ENROLL:
        case OPERATION_GETCERT:
        case OPERATION_GETCRL:
            res = (sMime.find(MIME_PKI)
                   != std::string::npos);
            break;
        case OPERATION_GETNEXTCA:
            res = (sMime.find(MIME_GETNEXT_CA)
                   != std::string::npos);
            break;
        case OPERATION_GETCAPS:
            res = true;
            break;
        default:
            break;
    }
    return res;
}

bool ResponseMessage::VerifyContentType(RequestMessage requestMessage,
                                        const std::string &sMime) {
    OperationType type = requestMessage.GetOperationType();
    return VerifyContentType(type, sMime);
}


