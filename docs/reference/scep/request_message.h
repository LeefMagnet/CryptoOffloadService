// 
// Create by kong on 2024/5/30
// Copyright 2024 Beijing Xinchangcheng Technology Development Co., Ltd.
//
#ifndef CYBERLIB_BUILD_REQUEST_MESSAGE_H
#define CYBERLIB_BUILD_REQUEST_MESSAGE_H

#include "message.h"

namespace iwall {

class RequestMessage: Message {
public:
    explicit RequestMessage(OperationType operationType);

    void SetDirName(const std::string& sDirName) { dir_name_ = sDirName; }
    void SetQueryMessage(const std::string& sQueryMessage) { query_message_ = sQueryMessage; }

    OperationType GetOperationType() { return operation_type_; }

    // Encode Scep Url
    std::string EncodeMessage();

private:
    // URI Method GET and POST， default is GET.
    std::string request_method_ = "GET";
    // URI dir name
    std::string dir_name_ = "/scep/pkiclient";
    // URI query operation string
    // GetCACert, PKIOperation
    std::string query_operation_ = "GetCACert";
    // URI query message string
    std::string query_message_;
    OperationType operation_type_ = OPERATION_GETCA;
};

}

#endif //CYBERLIB_BUILD_REQUEST_MESSAGE_H
