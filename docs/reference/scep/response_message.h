// 
// Create by kong on 2024/5/30
// Copyright 2024 Beijing Xinchangcheng Technology Development Co., Ltd.
//
#ifndef CYBERLIB_BUILD_RESPONSE_MESSAGE_H
#define CYBERLIB_BUILD_RESPONSE_MESSAGE_H

#include "message.h"
#include "request_message.h"

namespace iwall {

class ResponseMessage : Message {
public:
    static bool VerifyContentType(OperationType operationType, const std::string &sMime);
    static bool VerifyContentType(RequestMessage requestMessage, const std::string &sMime);

};

}


#endif //CYBERLIB_BUILD_RESPONSE_MESSAGE_H
