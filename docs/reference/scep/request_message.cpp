// 
// Create by kong on 2024/5/30
// Copyright 2024 Beijing Xinchangcheng Technology Development Co., Ltd.
//

#include "request_message.h"

using namespace iwall;

RequestMessage::RequestMessage(OperationType operationType) {
    operation_type_ = operationType;
    switch (operationType) {
        case OPERATION_GETCA:
            query_operation_ = "GetCACert";
            break;
        case OPERATION_ENROLL:
        case OPERATION_GETCERT:
        case OPERATION_GETCRL:
            query_operation_ = "PKIOperation";
            break;
        case OPERATION_GETNEXTCA:
            query_operation_ = "GetNextCACert";
            break;
        case OPERATION_GETCAPS:
            query_operation_ = "GetCACaps";
            break;
        default:
            query_operation_ = "";
            break;
    }
}

std::string RequestMessage::EncodeMessage() {
    std::string result;
    // dir name
    result += dir_name_;
    result += "?";
    result += "operation=" + query_operation_;
    // The query_message may be empty
    if (!query_message_.empty()) {
        result += "&message=" + query_message_;
    }
    return result;
}