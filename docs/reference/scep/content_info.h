// 
// Create by kong on 2024/5/29
// Copyright 2024 Beijing Xinchangcheng Technology Development Co., Ltd.
//
#ifndef CYBERLIB_BUILD_CONTENT_INFO_H
#define CYBERLIB_BUILD_CONTENT_INFO_H

#include <string>
#include <vector>

// Custom Struct for Request a certificate by alias
// CertAliasOrCn ::= CHOICE {
//   alias              [0] UTF8String   OPTIONAL,
//   commonName         [1] UTF8String   OPTIONAL
//}

namespace iwall {

class ContentInfo {
public:
    typedef enum {
        Alias,
        CommonName,
        SerialNumber
    } ContentInfoType;

    explicit ContentInfo(ContentInfoType type);
    ~ContentInfo();

    // Encode Der Content Info
    std::vector<unsigned char> EncodeData(const std::string &buffer) const;

private:
    ContentInfoType type_;
};
}

#endif //CYBERLIB_BUILD_CONTENT_INFO_H
