
#include <stdio.h>
#include <fstream>
#include <sstream>
#include <string>
#include <type_traits>
#include "Certificate.h"
#include "SignedEeEnrollmentCertRequest.h"
#include "SignedCertificateRequest.h"
#include "SignedEeEnrollmentCertResponse.h"
#include "ScopedEeEnrollmentCertResponse.h"
#include "SecuredRACertRequest.h"
#include "ScopedEeRaCertRequest.h"
#include "SecuredRACertResponse.h"
#include "ScopedRaEeCertResponse.h"
#include "ScopedElectorEndorsement.h"
#include "CrlContents.h"
#include "SecuredPseudonymCertProvisioningRequest.h"
#include "SignedPseudonymCertProvisioningRequest.h"
#include "SecuredPseudonymCertProvisioningAck.h"
#include "SignedPseudonymCertProvisioningAck.h"
#include "ScopedPseudonymCertProvisioningAck.h"
#include "SecuredAuthenticatedDownloadRequest.h"
#include "SignedAuthenticatedDownloadRequest.h"
#include "SecuredIdCertProvisioningRequest.h"
#include "SignedIdCertProvisioningRequest.h"
#include "SecuredIdCertProvisioningAck.h"
#include "SignedIdCertProvisioningAck.h"
#include "ScopedIdCertProvisioningAck.h"
#include "ToBeSignedEncryptedCertificateResponse.h"
#include "SignerIdentifier.h"
#include "SignedLocalCertificateChainFiles.h"
#include "ScopedLocalCertificateChainFiles.h"

#define ERRO_FD  stderr
#define INFO_FD  stdout

#define _echo(type, format, ...)              \
    do {                                      \
        fprintf(type, format, ##__VA_ARGS__); \
    } while (0)

#define echo(type, format, ...)                                            \
    do {                                                                   \
        _echo(type ## _FD, "%s %3d " format "\n",                       \
                    "[" #type "] ", __LINE__, ##__VA_ARGS__);           \
    } while (0)

#define USAGE                                   \
    "./encode\n\n"                              \
    "or\n\n"                                    \
    "./decode <input coer file> <type>\n"       \
    "  type:\n"                                 \
    "     1 - Certificate                     证书\n"                           \
    "     2 -                                 安全消息\n"                       \
    "     3 - SignedEeEnrollmentCertRequest   ec 请求\n"                        \
    "     4 - SignedCertificateRequest        ec 请求中序列化串结构体\n"        \
    "     5 - SignedEeEnrollmentCertResponse  ec 响应\n"                        \
    "     6 - ScopedEeEnrollmentCertResponse  ec 响应中序列化串结构体\n"        \
    "     7 - SecuredRACertRequest            ra 请求\n"                        \
    "     8 - ScopedEeRaCertRequest           ra 请求中序列化串结构体\n"        \
    "     9 - SecuredRACertResponse           ra 响应\n"                        \
    "    10 - ScopedRaEeCertResponse          ra 响应中序列化串结构体之一\n"    \
    "    11 - ScopedElectorEndorsement        ra 响应中序列化串结构体之二\n"    \
    "    12 - CrlContents                     ra 响应中序列化串结构体之三\n"    \
    "    13 - SecuredPseudonymCertProvisioningRequest   pc 申请\n"              \
    "    14 - SignedPseudonymCertProvisioningRequest    pc 申请中的加密部分\n"  \
    "    15 - SecuredPseudonymCertProvisioningAck       pc 确认\n"              \
    "    16 - SignedPseudonymCertProvisioningAck        pc 确认中的加密部分\n"  \
    "    17 - ScopedPseudonymCertProvisioningAck        pc 确认中加密部分明文中序列化串结构体\n"  \
    "    18 - SecuredAuthenticatedDownloadRequest       pc 下载请求\n"          \
    "    19 - SignedAuthenticatedDownloadRequest        pc 下载请求中的加密部分\n"                \
    "    20 - SecuredIdCertProvisioningRequest          ic 请求\n"              \
    "    21 - SignedIdCertProvisioningRequest           ic 请求中的加密部分\n"  \
    "    22 - SecuredIdCertProvisioningAck              ic 确认\n"              \
    "    23 - SignedIdCertProvisioningAck               ic 确认中的加密部分\n"  \
    "    24 - ScopedIdCertProvisioningAck               ic 确认中加密部分明文中序列化串结构体\n"  \
    "    25 - ToBeSignedEncryptedCertificateResponse\n"                         \
    "    26 - SignerIdentifier\n"                                               \
    "    27 - SignedLocalCertificateChainFiles\n"                                               \
    "    28 - ScopedLocalCertificateChainFiles\n"                                               \
    "\n"

template <typename T>
int decode(const std::string& strStream)
{
    asn_dec_rval_t rval;
    T* pstruct = nullptr;

    asn_TYPE_descriptor_t td;   
    if (std::is_same<typename std::decay<T>::type, Certificate_t>::value) {
        td = asn_DEF_Certificate;
    } else if (std::is_same<typename std::decay<T>::type, SignedEeEnrollmentCertRequest_t>::value) {
        td = asn_DEF_SignedEeEnrollmentCertRequest;
    } else if (std::is_same<typename std::decay<T>::type, SignedCertificateRequest_t>::value) {
        td = asn_DEF_SignedCertificateRequest;
    } else if (std::is_same<typename std::decay<T>::type, SignedEeEnrollmentCertResponse_t>::value) {
        td = asn_DEF_SignedEeEnrollmentCertResponse;
    } else if (std::is_same<typename std::decay<T>::type, ScopedEeEnrollmentCertResponse_t>::value) {
        td = asn_DEF_ScopedEeEnrollmentCertResponse;
    } else if (std::is_same<typename std::decay<T>::type, SecuredRACertRequest_t>::value) {
        td = asn_DEF_SecuredRACertRequest;
    } else if (std::is_same<typename std::decay<T>::type, ScopedEeRaCertRequest_t>::value) {
        td = asn_DEF_ScopedEeRaCertRequest;
    } else if (std::is_same<typename std::decay<T>::type, SecuredRACertResponse_t>::value) {
        td = asn_DEF_SecuredRACertResponse;
    } else if (std::is_same<typename std::decay<T>::type, ScopedRaEeCertResponse_t>::value) {
        td = asn_DEF_ScopedRaEeCertResponse;
    } else if (std::is_same<typename std::decay<T>::type, ScopedElectorEndorsement_t>::value) {
        td = asn_DEF_ScopedElectorEndorsement;
    } else if (std::is_same<typename std::decay<T>::type, CrlContents_t>::value) {
        td = asn_DEF_CrlContents;
    } else if (std::is_same<typename std::decay<T>::type, SecuredPseudonymCertProvisioningRequest_t>::value) {
        td = asn_DEF_SecuredPseudonymCertProvisioningRequest;
    } else if (std::is_same<typename std::decay<T>::type, SignedPseudonymCertProvisioningRequest_t>::value) {
        td = asn_DEF_SignedPseudonymCertProvisioningRequest;
    } else if (std::is_same<typename std::decay<T>::type, SecuredPseudonymCertProvisioningAck_t>::value) {
        td = asn_DEF_SecuredPseudonymCertProvisioningAck;
    } else if (std::is_same<typename std::decay<T>::type, SignedPseudonymCertProvisioningAck_t>::value) {
        td = asn_DEF_SignedPseudonymCertProvisioningAck;
    } else if (std::is_same<typename std::decay<T>::type, ScopedPseudonymCertProvisioningAck_t>::value) {
        td  = asn_DEF_ScopedPseudonymCertProvisioningAck;
    } else if (std::is_same<typename std::decay<T>::type, SecuredAuthenticatedDownloadRequest_t>::value) {
        td = asn_DEF_SecuredAuthenticatedDownloadRequest;
    } else if (std::is_same<typename std::decay<T>::type, SignedAuthenticatedDownloadRequest_t>::value) {
        td = asn_DEF_SignedAuthenticatedDownloadRequest;
    } else if (std::is_same<typename std::decay<T>::type, SecuredIdCertProvisioningRequest_t>::value) {
        td = asn_DEF_SecuredIdCertProvisioningRequest;
    } else if (std::is_same<typename std::decay<T>::type, SignedIdCertProvisioningRequest_t>::value) {
        td = asn_DEF_SignedIdCertProvisioningRequest;
    } else if (std::is_same<typename std::decay<T>::type, SecuredIdCertProvisioningAck_t>::value) {
        td = asn_DEF_SecuredIdCertProvisioningAck;
    } else if (std::is_same<typename std::decay<T>::type, SignedIdCertProvisioningAck_t>::value) {
        td = asn_DEF_SignedIdCertProvisioningAck;
    } else if (std::is_same<typename std::decay<T>::type, ScopedIdCertProvisioningAck_t>::value) {
        td = asn_DEF_ScopedIdCertProvisioningAck;
    } else if (std::is_same<typename std::decay<T>::type, ToBeSignedEncryptedCertificateResponse_t>::value) {
        td = asn_DEF_ToBeSignedEncryptedCertificateResponse;
    } else if (std::is_same<typename std::decay<T>::type, SignerIdentifier_t>::value) {
        td = asn_DEF_SignerIdentifier;
    } else if (std::is_same<typename std::decay<T>::type, SignedLocalCertificateChainFiles_t>::value) {
        td = asn_DEF_SignedLocalCertificateChainFiles;
    } else if (std::is_same<typename std::decay<T>::type, ScopedLocalCertificateChainFiles_t>::value) {
        td = asn_DEF_ScopedLocalCertificateChainFiles;
    } else {
        echo(ERRO, "unsupported type");
        return -1;
    }
    
    rval = oer_decode(0, &td,
                      (void**)&pstruct,
                      strStream.c_str(),
                      strStream.size());
    if (rval.code != RC_OK) {
        echo(ERRO, "oer_decode failed");
        return -1;
    }
    
    xer_fprint(stdout, &td, pstruct);

    if (pstruct) {
        ASN_STRUCT_FREE(td, pstruct);
    }

    return 0;
}

int main(int argc, char* argv[])
{
    if (argc != 3) {
        printf(USAGE);
        return -1;
    }
    
    std::ifstream ifs(argv[1], std::ifstream::in | std::ifstream::binary);
    if (! ifs.is_open()) {
        echo(ERRO, "open %s failed", argv[1]);
        return -1;
    }
    
    std::ostringstream oss;
    
    oss << ifs.rdbuf();
    ifs.close();
    
    std::string stream(oss.str());
    int type = atoi(argv[2]);
    int ret;
    
    if (type == 1) {
        ret = decode<Certificate_t>(stream);
    } else if (type == 3) {
        ret = decode<SignedEeEnrollmentCertRequest_t>(stream);
    } else if (type == 4) {
        ret = decode<SignedCertificateRequest_t>(stream);
    } else if (type == 5) {
        ret = decode<SignedEeEnrollmentCertResponse_t>(stream);
    } else if (type == 6) {
        ret = decode<ScopedEeEnrollmentCertResponse_t>(stream);
    } else if (type == 7) {
        ret = decode<SecuredRACertRequest_t>(stream);
    } else if (type == 8) {
        ret = decode<ScopedEeRaCertRequest_t>(stream);
    } else if (type == 9) {
        ret = decode<SecuredRACertResponse_t>(stream);
    } else if (type == 10) {
        ret = decode<ScopedRaEeCertResponse_t>(stream);
    } else if (type == 11) {
        ret = decode<ScopedElectorEndorsement_t>(stream);
    } else if (type == 12) {
        ret = decode<CrlContents_t>(stream);
    } else if (type == 13) {
        ret = decode<SecuredPseudonymCertProvisioningRequest_t>(stream);
    } else if (type == 14) {
        ret = decode<SignedPseudonymCertProvisioningRequest_t>(stream);
    } else if (type == 15) {
        ret = decode<SecuredPseudonymCertProvisioningAck_t>(stream);
    } else if (type == 16) {
        ret = decode<SignedPseudonymCertProvisioningAck_t>(stream);
    } else if (type == 17) {
        ret = decode<ScopedPseudonymCertProvisioningAck_t>(stream);
    } else if (type == 18) {
        ret = decode<SecuredAuthenticatedDownloadRequest_t>(stream);
    } else if (type == 19) {
        ret = decode<SignedAuthenticatedDownloadRequest_t>(stream);
    } else if (type == 20) {
        ret = decode<SecuredIdCertProvisioningRequest_t>(stream);
    } else if (type == 21) {
        ret = decode<SignedIdCertProvisioningRequest_t>(stream);
    } else if (type == 22) {
        ret = decode<SecuredIdCertProvisioningAck_t>(stream);
    } else if (type == 23) {
        ret = decode<SignedIdCertProvisioningAck_t>(stream);
    } else if (type == 24) {
        ret = decode<ScopedIdCertProvisioningAck_t>(stream);
    } else if (type == 25) {
        ret = decode<ToBeSignedEncryptedCertificateResponse_t>(stream);
    } else if (type == 26) {
        ret = decode<SignerIdentifier_t>(stream);
    } else if (type == 27) {
        ret = decode<SignedLocalCertificateChainFiles_t>(stream);
    } else if (type == 28) {
        ret = decode<ScopedLocalCertificateChainFiles_t>(stream);
    } else {
        echo(ERRO, "unsupported type");
        return -1;
    }
    
    if (ret != 0) {
        echo(ERRO, "decode failed");
    } else {
        echo(INFO, "decode success");
    }
    
    return 0;
}