// 
// Create by kong on 2024/7/15
// Copyright 2024 Beijing Xinchangcheng Technology Development Co., Ltd.
//
#ifndef CYBERLIB_BUILD_SCEP_MESSAGE_H
#define CYBERLIB_BUILD_SCEP_MESSAGE_H

#include <string>

namespace iwall {

class ScepMessage {
public:
    typedef enum {
        OPERATION_GETCA     = 1,
        OPERATION_GETCARA   = 2,
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

    static std::string GetScepMime(OperationType operation);
};

}


#endif //CYBERLIB_BUILD_SCEP_MESSAGE_H
