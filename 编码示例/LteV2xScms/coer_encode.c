
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
// ec 请求
#include "SignedEeEnrollmentCertRequest.h"
#include "SignedCertificateRequest.h"
// ec 响应
#include "SignedEeEnrollmentCertResponse.h"
#include "ScopedEeEnrollmentCertResponse.h"
// ra 请求
#include "SecuredRACertRequest.h"
#include "ScopedEeRaCertRequest.h"
// ra 响应
#include "SecuredRACertResponse.h"
#include "ScopedRaEeCertResponse.h"
#include "ScopedElectorEndorsement.h"
#include "CrlContents.h"
// pc 请求
#include "SecuredPseudonymCertProvisioningRequest.h"
#include "SignedPseudonymCertProvisioningRequest.h"
// pc 确认
#include "SecuredPseudonymCertProvisioningAck.h"
#include "SignedPseudonymCertProvisioningAck.h"
#include "ScopedPseudonymCertProvisioningAck.h"
// pc 下载请求
#include "SecuredAuthenticatedDownloadRequest.h"
#include "SignedAuthenticatedDownloadRequest.h"
// ic 请求
#include "SecuredIdCertProvisioningRequest.h"
#include "SignedIdCertProvisioningRequest.h"
// ic 响应
#include "SecuredIdCertProvisioningAck.h"
#include "SignedIdCertProvisioningAck.h"
#include "ScopedIdCertProvisioningAck.h"

#define STOP_IT_IF_ERROR(assertion, variable, format, ...)      \
    do {                                                        \
        if (assertion) {                                        \
            fprintf(stderr, "%d %s ", __LINE__, #variable);     \
            fprintf(stderr, format, ##__VA_ARGS__);             \
            goto cleanup;                                       \
        }                                                       \
    } while (0)

#define LOG_ERR(variable, format, ...)                          \
    do {                                                        \
        fprintf(stderr, "%d %s ", __LINE__, #variable);         \
        fprintf(stderr, format, ##__VA_ARGS__);                 \
    } while(0)

#define FILL_WITH_OCTET_STRING(Ivalue, Ibuf, Isize, oRet)       \
    do {                                                        \
        OCTET_STRING_t ostr;                                    \
        memset(&ostr, 0, sizeof(OCTET_STRING_t));               \
        oRet = OCTET_STRING_fromBuf(&ostr, Ibuf, Isize);        \
        Ivalue = ostr;                                          \
    } while (0)

/** 数组尺寸 */
#define XSIZE               1
#define YSIZE               1
        
/** 固定参数 */
#define EeEcaReqVersion     1
#define EcaResVersion       1
#define ProtocolVersion     3
#define CertificateVersion  3
#define ScmsPDUVersion      1
#define EeRaCertReqVersion  1
#define EeRaCertResVersion  1
#define CrlContentVersion   1
#define RaPseCertReqVersion 1
#define RaPseCertAckVersion 1
#define EeRaIdCertReqVersion    1

#define PsidValue           0x23
#define CrlPsidValue        0x100

#define ONESIZE             1

/** 缺省参数 */
#define DEFAULT_MIN_CHAIN_LENGHT    1
#define DEFAULT_CHAIN_LENGHT_RANGE  0

/** 缓冲区长度选择 */
#define BUF4KSIZE       4096
#define BUF8KSIZE       8192
#define BUF1XSIZE       10240
#define BUF2XSIZE       20480

#define OERBUFSIZE      BUF8KSIZE
    

/**
 * 编译命令:
 *      cc -g -O0 -I. *.c -D_DEFAULT_SOURCE -o mycoer
 * 内存泄漏测试:
 *      valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./mycoer
 *      测试结果为编解码均无内存泄漏
 * 约束校验测试
 *
 * 健壮性测试
 *    编码或解码完成后，应该进行多次循环测试(不下 100 次)，以保证其健壮性。
 *
 * 编码注意 - 不透明指针问题:
 *    union 类型结构体 Ieee1609Dot2Content 名字为 signedCertificateRequest 的成员其类型为
 *    Opaque_t，是一个 OCTET_STRING_t，即一个字符串。但实际上它是一个结构体的二进制序列化
 *    表示，应该将其看作一个类似于 C 语言中的不透明指针。
 *    如果在编码时将 signedCertificateRequest 成员在栈中分配内存，则最后释放时会因为结构体
 *    被擦除(变为字符串)而产生内存泄漏。
 *    正确的方法是将该成员以结构体的形式在堆中分配内存，最后再调用 ASN_STRUCT_FREE 释放该
 *    结构体。
 *
 */

static const unsigned char ucs[] = {
                        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
                        'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                        'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
                        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                        'Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S', 'R', 'Q', 'P', 'O',
                        'N', 'M', 'L', 'K', 'J', 'I', 'H', 'G', 'F', 'E', 'D', 'C', 'B', 'A',
                        'z', 'y', 'x', 'w', 'v', 'u', 't', 's', 'r', 'q', 'p', 'o',
                        'n', 'm', 'l', 'k', 'j', 'i', 'h', 'g', 'f', 'e', 'd', 'c', 'b', 'a',
                        '9', '8', '7', '6', '5', '4', '3', '2', '1', '0'
                        };
        
static int write_callback(const void *buffer, size_t size, void *app_key)
{
    FILE *fp = app_key;
    size_t wrote = fwrite(buffer, 1, size, fp);
    return (wrote == size) ? 0 : -1;
}

int encode_SignedEeEnrollmentCertRequest()
{
    int ret = -1;
    
    SignedEeEnrollmentCertRequest_t* pstSignedEeEnrollmentCertRequest = NULL;
    
    pstSignedEeEnrollmentCertRequest = 
                                    calloc(1, sizeof(SignedEeEnrollmentCertRequest_t));
    STOP_IT_IF_ERROR(NULL == pstSignedEeEnrollmentCertRequest, 
                     SignedEeEnrollmentCertRequest_t, 
                     "calloc failed\n");
    // Field: protocolVersion
    pstSignedEeEnrollmentCertRequest->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_signedCertificateRequest;  
    
    /** 不透明指针 - SignedCertificateRequest */
    struct SignedCertificateRequest* pstSignedCertificateRequest = NULL;
    pstSignedCertificateRequest = calloc(1, sizeof(struct SignedCertificateRequest));
    STOP_IT_IF_ERROR(NULL == pstSignedCertificateRequest, 
                     SignedCertificateRequest_t, 
                     "calloc failed\n");
    
    pstSignedCertificateRequest->hashId = HashAlgorithm_sm3;
    pstSignedCertificateRequest->tbsRequest.version = ScmsPDUVersion;
    pstSignedCertificateRequest->tbsRequest.content
                            .present = ScmsPDU__content_PR_eca_ee;
    pstSignedCertificateRequest->tbsRequest.content
                            .choice.eca_ee
                                .present = EcaEndEntityInterfacePDU_PR_eeEcaCertRequest;
    pstSignedCertificateRequest->tbsRequest.content
                            .choice.eca_ee
                                .choice.eeEcaCertRequest
                                    .version = EeEcaReqVersion;
    pstSignedCertificateRequest->tbsRequest.content
                            .choice.eca_ee
                                .choice.eeEcaCertRequest
                                    .currentTime = 0x123456;
    pstSignedCertificateRequest->tbsRequest.content
                            .choice.eca_ee
                                .choice.eeEcaCertRequest
                                    .tbsData
                                        .id.present = CertificateId_PR_name;        // 有问题
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->tbsRequest.content
                            .choice.eca_ee
                                .choice.eeEcaCertRequest
                                    .tbsData
                                        .id.choice.name, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, Hostname_t, "OCTET_STRING_fromBuf failed\n");
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->tbsRequest.content
                            .choice.eca_ee
                                .choice.eeEcaCertRequest
                                    .tbsData
                                        .cracaId, ucs, 3, ret);

    pstSignedCertificateRequest->tbsRequest.content
                            .choice.eca_ee
                                .choice.eeEcaCertRequest
                                    .tbsData
                                        .crlSeries = 15511;
    pstSignedCertificateRequest->tbsRequest.content
                            .choice.eca_ee
                                .choice.eeEcaCertRequest
                                    .tbsData
                                        .validityPeriod
                                            .start = 0x123456;
    pstSignedCertificateRequest->tbsRequest.content
                            .choice.eca_ee
                                .choice.eeEcaCertRequest
                                    .tbsData
                                        .validityPeriod
                                            .duration.present = Duration_PR_years;
                                    
    pstSignedCertificateRequest->tbsRequest.content
                            .choice.eca_ee
                                .choice.eeEcaCertRequest
                                    .tbsData
                                        .validityPeriod
                                            .duration.choice.years = 11;

    struct GeographicRegion* pstGeographicRegion = NULL;
    pstGeographicRegion = calloc(1, sizeof(struct GeographicRegion));
    STOP_IT_IF_ERROR(NULL == pstGeographicRegion, 
                     GeographicRegion_t, 
                     "calloc failed\n");
    pstGeographicRegion->present = GeographicRegion_PR_circularRegion;
    pstGeographicRegion->choice.circularRegion.center.latitude = -12345;
    pstGeographicRegion->choice.circularRegion.center.longitude = 67890;
    pstGeographicRegion->choice.circularRegion.radius = 100;
    pstSignedCertificateRequest->tbsRequest.content
                            .choice.eca_ee
                                .choice.eeEcaCertRequest
                                    .tbsData
                                        .region = pstGeographicRegion;

    struct SequenceOfPsidGroupPermissions* pstSequenceOfPsidGroupPermissions = NULL;
    pstSequenceOfPsidGroupPermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
    STOP_IT_IF_ERROR(NULL == pstSequenceOfPsidGroupPermissions, 
                     SequenceOfPsidGroupPermissions_t, 
                     "calloc failed\n");
    struct PsidGroupPermissions* parrPsidGroupPermissions[XSIZE] = { NULL };
    int i;
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrPsidGroupPermissions[i]) {
            parrPsidGroupPermissions[i] = calloc(1, sizeof(struct PsidGroupPermissions));
            STOP_IT_IF_ERROR(NULL == parrPsidGroupPermissions[i], 
                             PsidGroupPermissions_t,
                             "calloc failed\n");
        }
        parrPsidGroupPermissions[i]->subjectPermissions.present = SubjectPermissions_PR_all;
        parrPsidGroupPermissions[i]->subjectPermissions.choice.all = 0;
        
        if (NULL == parrPsidGroupPermissions[i]->minChainLength) {
            parrPsidGroupPermissions[i]->minChainLength = calloc(1, sizeof(long));
            STOP_IT_IF_ERROR(NULL == parrPsidGroupPermissions[i]->minChainLength, 
                             long_t,
                             "calloc failed\n");
        }
        *parrPsidGroupPermissions[i]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
        
        parrPsidGroupPermissions[i]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
        
        if (NULL == parrPsidGroupPermissions[i]->eeType) {
            parrPsidGroupPermissions[i]->eeType = calloc(1, sizeof(EndEntityType_t));
            STOP_IT_IF_ERROR(NULL == parrPsidGroupPermissions[i]->eeType, 
                             EndEntityType_t,
                             "calloc failed\n");
        }
        if (NULL == parrPsidGroupPermissions[i]->eeType->buf) {
            parrPsidGroupPermissions[i]->eeType->buf = calloc(1, 1);
            STOP_IT_IF_ERROR(NULL == parrPsidGroupPermissions[i]->eeType->buf, 
                             uint8_t,
                             "calloc failed\n");
        }
        parrPsidGroupPermissions[i]->eeType->size = 1;
        parrPsidGroupPermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
        parrPsidGroupPermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
        parrPsidGroupPermissions[i]->eeType->bits_unused = 6;
        
        ret = asn_set_add(&pstSequenceOfPsidGroupPermissions->list, parrPsidGroupPermissions[i]);
        STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
    }
    pstSignedCertificateRequest->tbsRequest
                    .content.choice.eca_ee
                        .choice.eeEcaCertRequest
                            .tbsData
                                .certRequestPermissions = pstSequenceOfPsidGroupPermissions;
    
    pstSignedCertificateRequest->tbsRequest
                    .content.choice.eca_ee
                        .choice.eeEcaCertRequest
                            .tbsData
                                .verifyKeyIndicator
                                    .present = VerificationKeyIndicator_PR_verificationKey;
    pstSignedCertificateRequest->tbsRequest
                    .content.choice.eca_ee
                        .choice.eeEcaCertRequest
                            .tbsData
                                .verifyKeyIndicator
                                    .choice.verificationKey
                                        .present = PublicVerificationKey_PR_ecsigSm2;
    pstSignedCertificateRequest->tbsRequest
                    .content.choice.eca_ee
                        .choice.eeEcaCertRequest
                            .tbsData
                                .verifyKeyIndicator
                                    .choice.verificationKey
                                        .choice.ecsigSm2
                                            .present = EccP256CurvePoint_PR_x_only;
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->tbsRequest
                    .content.choice.eca_ee
                        .choice.eeEcaCertRequest
                            .tbsData
                                .verifyKeyIndicator
                                    .choice.verificationKey
                                        .choice.ecsigSm2
                                            .choice.x_only, ucs, 32, ret);                  
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");  
    
    pstSignedCertificateRequest->signer.present = SignerIdentifier_PR_self;
    pstSignedCertificateRequest->signer.choice.self = 0;

    pstSignedCertificateRequest->signature
                    .present = Signature_PR_sm2Signature;
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->signature
                    .choice.sm2Signature.r, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->signature
                    .choice.sm2Signature.s, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    char oerbuf[OERBUFSIZE] = { 0 };
    size_t oerlen = 0;
    asn_enc_rval_t ec = oer_encode_to_buffer(&asn_DEF_SignedCertificateRequest,
                                             NULL,
                                             pstSignedCertificateRequest,
                                             oerbuf,
                                             OERBUFSIZE);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode_to_buffer,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    oerlen = ec.encoded;

    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.signedCertificateRequest,
                           oerbuf, 
                           oerlen,
                           ret);
    STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");
    
    pstSignedEeEnrollmentCertRequest->content = pstIeee1609Dot2Content;
    
    /** 测试 */
    FILE* fp = fopen("SignedEeEnrollmentCertRequest.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_SignedEeEnrollmentCertRequest,
                    pstSignedEeEnrollmentCertRequest,
                    write_callback,
                    (void*)fp);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");

    if (fp) fclose(fp);
    fp = fopen("SignedCertificateRequest.ecreq.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_SignedCertificateRequest,
                    pstSignedCertificateRequest,
                    write_callback,
                    (void*)fp);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
                    
    // xml print SignedEeEnrollmentCertRequest_t
    xer_fprint(stdout, &asn_DEF_SignedEeEnrollmentCertRequest,
                        pstSignedEeEnrollmentCertRequest);
    // xml print SignedCertificateRequest_t
    xer_fprint(stdout, &asn_DEF_SignedCertificateRequest, pstSignedCertificateRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode ec request success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedEeEnrollmentCertRequest, 
                    pstSignedEeEnrollmentCertRequest);
    ASN_STRUCT_FREE(asn_DEF_SignedCertificateRequest, pstSignedCertificateRequest);
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free ec request success ====\n");
    
    return ret;
}

int decode_SignedEeEnrollmentCertRequest(const unsigned char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SignedEeEnrollmentCertRequest_t* pstSignedEeEnrollmentCertRequest = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SignedEeEnrollmentCertRequest, 
                      (void**)&pstSignedEeEnrollmentCertRequest,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SignedEeEnrollmentCertRequest, pstSignedEeEnrollmentCertRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SignedEeEnrollmentCertRequest_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedEeEnrollmentCertRequest, pstSignedEeEnrollmentCertRequest);
    
    if (0 == ret) fprintf(stdout, "==== free SignedEeEnrollmentCertRequest_t success ====\n");
    
    return ret;
}

int decode_SignedCertificateRequest(const unsigned char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SignedCertificateRequest_t* pstSignedCertificateRequest = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SignedCertificateRequest, 
                      (void**)&pstSignedCertificateRequest,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SignedCertificateRequest, pstSignedCertificateRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SignedCertificateRequest_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedCertificateRequest, pstSignedCertificateRequest);
    
    if (0 == ret) fprintf(stdout, "==== free SignedCertificateRequest_t success ====\n");
    
    return ret;
}

int encode_SignedEeEnrollmentCertResponse()
{
    int ret = -1, i = 0;
    SignedEeEnrollmentCertResponse_t* pstSignedEeEnrollmentCertResponse = NULL;
    
    pstSignedEeEnrollmentCertResponse = calloc(1, sizeof(SignedEeEnrollmentCertResponse_t));
    STOP_IT_IF_ERROR(NULL == pstSignedEeEnrollmentCertResponse, 
                     SignedEeEnrollmentCertResponse_t, 
                     "calloc failed\n");
    
    // Field: protocolVersion
    pstSignedEeEnrollmentCertResponse->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_signedData;
    
    struct SignedData* pstSignedData = NULL;
    pstSignedData = calloc(1, sizeof(struct SignedData));
    STOP_IT_IF_ERROR(NULL == pstSignedData,
                     SignedData_t, 
                     "calloc failed\n");

    pstSignedData->hashId = HashAlgorithm_sm3;
    
    struct ToBeSignedData* pstToBeSignedData = NULL;
    pstToBeSignedData = calloc(1, sizeof(struct ToBeSignedData));
    STOP_IT_IF_ERROR(NULL == pstToBeSignedData, 
                     ToBeSignedData_t, 
                     "calloc failed\n");
        
    struct SignedDataPayload* pstSignedDataPayload = NULL;
    pstSignedDataPayload = calloc(1, sizeof(struct SignedDataPayload));
    STOP_IT_IF_ERROR(NULL == pstSignedDataPayload, 
                     SignedDataPayload_t, 
                     "calloc failed\n");
    
    struct Ieee1609Dot2Data* pstIeee1609Dot2Data = NULL;
    pstIeee1609Dot2Data = calloc(1, sizeof(struct Ieee1609Dot2Data));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Data, 
                     Ieee1609Dot2Data_t, 
                     "calloc failed\n");
    
    pstIeee1609Dot2Data->protocolVersion = ProtocolVersion;
    
    struct Ieee1609Dot2Content* pstIeee1609Dot2ContentUnsecuredData = NULL;
    pstIeee1609Dot2ContentUnsecuredData = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2ContentUnsecuredData, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2ContentUnsecuredData->present = Ieee1609Dot2Content_PR_unsecuredData;
    /** 
        1. unsecured 的填充内容是 ScopedEeEnrollmentCertResponse 结构的序列化。
        2. unsecured 这里应该理解为一个不透明指针，所以应该在堆中分配内存，最后也应该显式
           调用 ASN_STRUCT_FREE 函数释放。
     */
    ScopedEeEnrollmentCertResponse_t* pstScopedEeEnrollmentCertResponse = NULL;
    pstScopedEeEnrollmentCertResponse = calloc(1, sizeof(ScopedEeEnrollmentCertResponse_t));
    STOP_IT_IF_ERROR(NULL == pstScopedEeEnrollmentCertResponse, 
                     ScopedEeEnrollmentCertResponse_t, 
                     "calloc failed\n");

    pstScopedEeEnrollmentCertResponse->version = ScmsPDUVersion;
    pstScopedEeEnrollmentCertResponse->content
                            .present = ScmsPDU__content_PR_eca_ee;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .present = EcaEndEntityInterfacePDU_PR_ecaEeCertResponse;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .version = EcaResVersion;
    FILL_WITH_OCTET_STRING(
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .requestHash, ucs, 8, ret);
    STOP_IT_IF_ERROR(0 != ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .version = CertificateVersion;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .type = CertificateType_implicit;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .issuer.present = IssuerIdentifier_PR_self;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .issuer.choice.self = HashAlgorithm_sm3;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .toBeSigned.id
                                            .present = CertificateId_PR_none;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .toBeSigned.id
                                            .choice.none = 0;                                           
    FILL_WITH_OCTET_STRING(
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .toBeSigned.cracaId, ucs, 3, ret);
    STOP_IT_IF_ERROR(0 != ret, HashedId3_t, "OCTET_STRING_fromBuf failed\n");
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .toBeSigned
                                            .crlSeries = 65511;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .toBeSigned
                                            .validityPeriod.start = 0x123456;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .toBeSigned
                                            .validityPeriod.duration
                                                .present = Duration_PR_years;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .toBeSigned
                                            .validityPeriod.duration
                                                .choice.years = 14;

    struct SequenceOfPsidSsp* pstAppPermissions = NULL;
    pstAppPermissions = calloc(1, sizeof(struct SequenceOfPsidSsp));
    STOP_IT_IF_ERROR(NULL == pstAppPermissions,
                     SequenceOfPsidSsp_t,
                     "calloc failed\n");
    
    struct PsidSsp* parrPsidSsp[XSIZE] = { NULL };
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrPsidSsp[i]) {
            parrPsidSsp[i] = calloc(1, sizeof(struct PsidSsp));
            STOP_IT_IF_ERROR(NULL == parrPsidSsp[i], PsidSsp_t, "calloc failed\n");
        }
        parrPsidSsp[i]->psid = 100;
        parrPsidSsp[i]->ssp = calloc(1, sizeof(struct ServiceSpecificPermissions));
        STOP_IT_IF_ERROR(NULL == parrPsidSsp[i]->ssp,
                         ServiceSpecificPermissions_t,
                         "calloc failed\n");
        parrPsidSsp[i]->ssp->present = ServiceSpecificPermissions_PR_opaque;
        FILL_WITH_OCTET_STRING(parrPsidSsp[i]->ssp->choice.opaque, ucs, -1, ret);
        STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        ret = asn_set_add(&pstAppPermissions->list, parrPsidSsp[i]);
        STOP_IT_IF_ERROR(0 != ret, ServiceSpecificPermissions_t, "asn_set_add failed\n");
    }
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .toBeSigned
                                            .appPermissions = pstAppPermissions;
    
    struct SequenceOfPsidGroupPermissions* pstCertIssuePermissions = NULL;
    pstCertIssuePermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
    STOP_IT_IF_ERROR(NULL == pstCertIssuePermissions, 
                     SequenceOfPsidGroupPermissions_t, 
                     "calloc failed\n");
    struct PsidGroupPermissions* parrCertIssuePermissions[XSIZE] = { NULL };
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrCertIssuePermissions[i]) {
            parrCertIssuePermissions[i] = calloc(1, sizeof(struct PsidGroupPermissions));
            STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[i], 
                             PsidGroupPermissions_t,
                             "calloc failed\n");
        }
        parrCertIssuePermissions[i]->subjectPermissions.present = SubjectPermissions_PR_all;
        parrCertIssuePermissions[i]->subjectPermissions.choice.all = 0;
        
        if (NULL == parrCertIssuePermissions[i]->minChainLength) {
            parrCertIssuePermissions[i]->minChainLength = calloc(1, sizeof(long));
            STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[i]->minChainLength, 
                             long_t,
                             "calloc failed\n");
        }
        *parrCertIssuePermissions[i]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
        
        parrCertIssuePermissions[i]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
        
        if (NULL == parrCertIssuePermissions[i]->eeType) {
            parrCertIssuePermissions[i]->eeType = calloc(1, sizeof(EndEntityType_t));
            STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[i]->eeType, 
                             EndEntityType_t,
                             "calloc failed\n");
        }
        if (NULL == parrCertIssuePermissions[i]->eeType->buf) {
            parrCertIssuePermissions[i]->eeType->buf = calloc(1, 1);
            STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[i]->eeType->buf, 
                             uint8_t,
                             "calloc failed\n");
        }
        parrCertIssuePermissions[i]->eeType->size = 1;
        parrCertIssuePermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
        parrCertIssuePermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
        parrCertIssuePermissions[i]->eeType->bits_unused = 6;
        
        ret = asn_set_add(&pstCertIssuePermissions->list, parrCertIssuePermissions[i]);
        STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
    }
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .toBeSigned
                                            .certIssuePermissions = pstCertIssuePermissions;
    
    struct SequenceOfPsidGroupPermissions* pstCertRequestPermissions = NULL;
    pstCertRequestPermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
    STOP_IT_IF_ERROR(NULL == pstCertRequestPermissions, 
                     SequenceOfPsidGroupPermissions_t, 
                     "calloc failed\n");
    struct PsidGroupPermissions* parrCertRequestPermissions[XSIZE] = { NULL };
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrCertRequestPermissions[i]) {
            parrCertRequestPermissions[i] = calloc(1, sizeof(struct PsidGroupPermissions));
            STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[i], 
                             PsidGroupPermissions_t,
                             "calloc failed\n");
        }
        parrCertRequestPermissions[i]->subjectPermissions.present = SubjectPermissions_PR_all;
        parrCertRequestPermissions[i]->subjectPermissions.choice.all = 0;
        
        if (NULL == parrCertRequestPermissions[i]->minChainLength) {
            parrCertRequestPermissions[i]->minChainLength = calloc(1, sizeof(long));
            STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[i]->minChainLength, 
                             long_t,
                             "calloc failed\n");
        }
        *parrCertRequestPermissions[i]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
        
        parrCertRequestPermissions[i]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
        
        if (NULL == parrCertRequestPermissions[i]->eeType) {
            parrCertRequestPermissions[i]->eeType = calloc(1, sizeof(EndEntityType_t));
            STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[i]->eeType, 
                             EndEntityType_t,
                             "calloc failed\n");
        }
        if (NULL == parrCertRequestPermissions[i]->eeType->buf) {
            parrCertRequestPermissions[i]->eeType->buf = calloc(1, 1);
            STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[i]->eeType->buf, 
                             uint8_t,
                             "calloc failed\n");
        }
        parrCertRequestPermissions[i]->eeType->size = 1;
        parrCertRequestPermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
        parrCertRequestPermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
        parrCertRequestPermissions[i]->eeType->bits_unused = 6;
        
        ret = asn_set_add(&pstCertRequestPermissions->list, parrCertRequestPermissions[i]);
        STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
    }
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .toBeSigned
                                            .certRequestPermissions = pstCertRequestPermissions;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .toBeSigned
                                            .verifyKeyIndicator
                                                .present = 
                                                    VerificationKeyIndicator_PR_reconstructionValue;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .toBeSigned
                                            .verifyKeyIndicator
                                                .choice.reconstructionValue
                                                    .present = EccP256CurvePoint_PR_x_only;
    FILL_WITH_OCTET_STRING(
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .ecaCert
                                        .toBeSigned
                                            .verifyKeyIndicator
                                                .choice.reconstructionValue
                                                        .choice.x_only, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .version = CertificateVersion;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .type = CertificateType_implicit;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .issuer.present = IssuerIdentifier_PR_self;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .issuer.choice.self = HashAlgorithm_sm3;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .toBeSigned.id
                                            .present = CertificateId_PR_none;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .toBeSigned.id
                                            .choice.none = 0;                                           
    FILL_WITH_OCTET_STRING(
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .toBeSigned.cracaId, ucs, 3, ret);
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .toBeSigned
                                            .crlSeries = 65511;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .toBeSigned
                                            .validityPeriod.start = time(NULL);
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .toBeSigned
                                            .validityPeriod.duration
                                                .present = Duration_PR_years;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .toBeSigned
                                            .validityPeriod.duration
                                                .choice.years = 14;
                                                
    struct SequenceOfPsidSsp* pstSubAppPermissions = NULL;
    pstSubAppPermissions = calloc(1, sizeof(struct SequenceOfPsidSsp));
    STOP_IT_IF_ERROR(NULL == pstSubAppPermissions,
                     SequenceOfPsidSsp_t,
                     "calloc failed\n");
    
    struct PsidSsp* parrSubPsidSsp[XSIZE] = { NULL };
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrSubPsidSsp[i]) {
            parrSubPsidSsp[i] = calloc(1, sizeof(struct PsidSsp));
            STOP_IT_IF_ERROR(NULL == parrSubPsidSsp[i], PsidSsp_t, "calloc failed\n");
        }
        parrSubPsidSsp[i]->psid = 100;
        parrSubPsidSsp[i]->ssp = calloc(1, sizeof(struct ServiceSpecificPermissions));
        STOP_IT_IF_ERROR(NULL == parrSubPsidSsp[i]->ssp,
                         ServiceSpecificPermissions_t,
                         "calloc failed\n");
        parrSubPsidSsp[i]->ssp->present = ServiceSpecificPermissions_PR_opaque;
        FILL_WITH_OCTET_STRING(parrSubPsidSsp[i]->ssp->choice.opaque, ucs, -1, ret);
        STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        ret = asn_set_add(&pstSubAppPermissions->list, parrSubPsidSsp[i]);
        STOP_IT_IF_ERROR(0 != ret, ServiceSpecificPermissions_t, "asn_set_add failed\n");
    }
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .toBeSigned
                                            .appPermissions = pstSubAppPermissions;
    
    struct SequenceOfPsidGroupPermissions* pstSubCertIssuePermissions = NULL;
    pstSubCertIssuePermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
    STOP_IT_IF_ERROR(NULL == pstSubCertIssuePermissions, 
                     SequenceOfPsidGroupPermissions_t, 
                     "calloc failed\n");
    struct PsidGroupPermissions* parrSubCertIssuePermissions[XSIZE] = { NULL };
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrSubCertIssuePermissions[i]) {
            parrSubCertIssuePermissions[i] = calloc(1, sizeof(struct PsidGroupPermissions));
            STOP_IT_IF_ERROR(NULL == parrSubCertIssuePermissions[i], 
                             PsidGroupPermissions_t,
                             "calloc failed\n");
        }
        parrSubCertIssuePermissions[i]->subjectPermissions.present = SubjectPermissions_PR_all;
        parrSubCertIssuePermissions[i]->subjectPermissions.choice.all = 0;
        
        if (NULL == parrSubCertIssuePermissions[i]->minChainLength) {
            parrSubCertIssuePermissions[i]->minChainLength = calloc(1, sizeof(long));
            STOP_IT_IF_ERROR(NULL == parrSubCertIssuePermissions[i]->minChainLength, 
                             long_t,
                             "calloc failed\n");
        }
        *parrSubCertIssuePermissions[i]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
        
        parrSubCertIssuePermissions[i]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
        
        if (NULL == parrSubCertIssuePermissions[i]->eeType) {
            parrSubCertIssuePermissions[i]->eeType = calloc(1, sizeof(EndEntityType_t));
            STOP_IT_IF_ERROR(NULL == parrSubCertIssuePermissions[i]->eeType, 
                             EndEntityType_t,
                             "calloc failed\n");
        }
        if (NULL == parrSubCertIssuePermissions[i]->eeType->buf) {
            parrSubCertIssuePermissions[i]->eeType->buf = calloc(1, 1);
            STOP_IT_IF_ERROR(NULL == parrSubCertIssuePermissions[i]->eeType->buf, 
                             uint8_t,
                             "calloc failed\n");
        }
        parrSubCertIssuePermissions[i]->eeType->size = 1;
        parrSubCertIssuePermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
        parrSubCertIssuePermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
        parrSubCertIssuePermissions[i]->eeType->bits_unused = 6;
        
        ret = asn_set_add(&pstSubCertIssuePermissions->list, parrSubCertIssuePermissions[i]);
        STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
    }
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .toBeSigned
                                            .certIssuePermissions = pstSubCertIssuePermissions;
    
    struct SequenceOfPsidGroupPermissions* pstSubCertRequestPermissions = NULL;
    pstSubCertRequestPermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
    STOP_IT_IF_ERROR(NULL == pstSubCertRequestPermissions, 
                     SequenceOfPsidGroupPermissions_t, 
                     "calloc failed\n");
    struct PsidGroupPermissions* parrSubCertRequestPermissions[XSIZE] = { NULL };
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrSubCertRequestPermissions[i]) {
            parrSubCertRequestPermissions[i] = calloc(1, sizeof(struct PsidGroupPermissions));
            STOP_IT_IF_ERROR(NULL == parrSubCertRequestPermissions[i], 
                             PsidGroupPermissions_t,
                             "calloc failed\n");
        }
        parrSubCertRequestPermissions[i]->subjectPermissions.present = SubjectPermissions_PR_all;
        parrSubCertRequestPermissions[i]->subjectPermissions.choice.all = 0;
        
        if (NULL == parrSubCertRequestPermissions[i]->minChainLength) {
            parrSubCertRequestPermissions[i]->minChainLength = calloc(1, sizeof(long));
            STOP_IT_IF_ERROR(NULL == parrSubCertRequestPermissions[i]->minChainLength, 
                             long_t,
                             "calloc failed\n");
        }
        *parrSubCertRequestPermissions[i]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
        
        parrSubCertRequestPermissions[i]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
        
        if (NULL == parrSubCertRequestPermissions[i]->eeType) {
            parrSubCertRequestPermissions[i]->eeType = calloc(1, sizeof(EndEntityType_t));
            STOP_IT_IF_ERROR(NULL == parrSubCertRequestPermissions[i]->eeType, 
                             EndEntityType_t,
                             "calloc failed\n");
        }
        if (NULL == parrSubCertRequestPermissions[i]->eeType->buf) {
            parrSubCertRequestPermissions[i]->eeType->buf = calloc(1, 1);
            STOP_IT_IF_ERROR(NULL == parrSubCertRequestPermissions[i]->eeType->buf, 
                             uint8_t,
                             "calloc failed\n");
        }
        parrSubCertRequestPermissions[i]->eeType->size = 1;
        parrSubCertRequestPermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
        parrSubCertRequestPermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
        parrSubCertRequestPermissions[i]->eeType->bits_unused = 6;
        
        ret = asn_set_add(&pstSubCertRequestPermissions->list, parrSubCertRequestPermissions[i]);
        STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
    }
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .toBeSigned
                                            .certRequestPermissions = pstSubCertRequestPermissions;

    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .toBeSigned
                                            .verifyKeyIndicator
                                                .present = 
                                                    VerificationKeyIndicator_PR_reconstructionValue;
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .toBeSigned
                                            .verifyKeyIndicator
                                                .choice.reconstructionValue
                                                    .present = EccP256CurvePoint_PR_x_only;
    FILL_WITH_OCTET_STRING(
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .enrollmentCert
                                        .toBeSigned
                                            .verifyKeyIndicator
                                                .choice.reconstructionValue
                                                    .choice.x_only, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    EccP256PrivateKeyReconstruction_t* pstEccP256PrivateKeyReconstruction = NULL;
    pstEccP256PrivateKeyReconstruction = calloc(1, sizeof(EccP256PrivateKeyReconstruction_t));
    STOP_IT_IF_ERROR(NULL == pstEccP256PrivateKeyReconstruction, 
                     EccP256PrivateKeyReconstruction_t, 
                     "calloc failed\n");
    FILL_WITH_OCTET_STRING(*pstEccP256PrivateKeyReconstruction, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, EccP256PrivateKeyReconstruction_t, "OCTET_STRING_fromBuf failed\n");
                     
    pstScopedEeEnrollmentCertResponse->content
                            .choice.eca_ee
                                .choice.ecaEeCertResponse
                                    .privKeyReconstruction = pstEccP256PrivateKeyReconstruction;
    
    char oerbuf[OERBUFSIZE] = { 0 };
    size_t oerlen = 0;
    asn_enc_rval_t ec = oer_encode_to_buffer(&asn_DEF_ScopedEeEnrollmentCertResponse,
                                             NULL,
                                             pstScopedEeEnrollmentCertResponse,
                                             oerbuf,
                                             OERBUFSIZE);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode_to_buffer,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    oerlen = ec.encoded;
        
    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2ContentUnsecuredData->choice.unsecuredData,
            oerbuf,
            oerlen,
            ret);
    STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");

    pstIeee1609Dot2Data->content = pstIeee1609Dot2ContentUnsecuredData;
    
    pstSignedDataPayload->data = pstIeee1609Dot2Data;
    // pstSignedDataPayload->extDataHash = ... // do nothing;
    
    pstToBeSignedData->payload = pstSignedDataPayload;
    pstToBeSignedData->headerInfo.psid = PsidValue;
    
    pstSignedData->tbsData = pstToBeSignedData;
    
    pstSignedData->signer.present = SignerIdentifier_PR_self;
    pstSignedData->signer.choice.self = 0;
    pstSignedData->signature
                    .present = Signature_PR_sm2Signature;
    FILL_WITH_OCTET_STRING(
    pstSignedData->signature
                    .choice.sm2Signature.r, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    FILL_WITH_OCTET_STRING(
    pstSignedData->signature
                    .choice.sm2Signature.s, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    pstIeee1609Dot2Content->choice.signedData = pstSignedData;
    pstSignedEeEnrollmentCertResponse->content = pstIeee1609Dot2Content;
    
    /** 测试 */
    FILE *fp = fopen("SignedEeEnrollmentCertResponse.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_SignedEeEnrollmentCertResponse,
                                     pstSignedEeEnrollmentCertResponse,
                                     write_callback,
                                     (void*)fp);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
                     
    if (fp) fclose(fp);
    fp = fopen("ScopedEeEnrollmentCertResponse.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_ScopedEeEnrollmentCertResponse,
                    pstScopedEeEnrollmentCertResponse,
                    write_callback,
                    (void*)fp);
    // xml print SignedEeEnrollmentCertResponse_t
    xer_fprint(stdout, &asn_DEF_SignedEeEnrollmentCertResponse, pstSignedEeEnrollmentCertResponse);
    // xml print ScopedEeEnrollmentCertResponse_t
    xer_fprint(stdout, &asn_DEF_ScopedEeEnrollmentCertResponse, pstScopedEeEnrollmentCertResponse);
    printf("\n");
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode ec response success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedEeEnrollmentCertResponse, pstSignedEeEnrollmentCertResponse);
    ASN_STRUCT_FREE(asn_DEF_ScopedEeEnrollmentCertResponse, pstScopedEeEnrollmentCertResponse);
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free ec response success ====\n");
    
    return ret;
}

int decode_SignedEeEnrollmentCertResponse(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SignedEeEnrollmentCertResponse_t* pstSignedEeEnrollmentCertResponse = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SignedEeEnrollmentCertResponse,
                      (void**)&pstSignedEeEnrollmentCertResponse,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SignedEeEnrollmentCertResponse, pstSignedEeEnrollmentCertResponse);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SignedEeEnrollmentCertResponse_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedEeEnrollmentCertResponse, pstSignedEeEnrollmentCertResponse);
    
    if (0 == ret) fprintf(stdout, "==== free SignedEeEnrollmentCertResponse_t success ====\n");
    
    return ret;
}

int decode_ScopedEeEnrollmentCertResponse(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    ScopedEeEnrollmentCertResponse_t* pstScopedEeEnrollmentCertResponse = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_ScopedEeEnrollmentCertResponse,
                      (void**)&pstScopedEeEnrollmentCertResponse,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_ScopedEeEnrollmentCertResponse, pstScopedEeEnrollmentCertResponse);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode ScopedEeEnrollmentCertResponse_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_ScopedEeEnrollmentCertResponse, pstScopedEeEnrollmentCertResponse);
    if (0 == ret) fprintf(stdout, "==== free ScopedEeEnrollmentCertResponse_t success ====\n");
    
    return ret;
}

int encode_SecuredRACertRequest()
{
    int ret = -1, i;
    SecuredRACertRequest_t* pstSecuredRACertRequest = NULL;
    
    pstSecuredRACertRequest = calloc(1, sizeof(SecuredRACertRequest_t));
    STOP_IT_IF_ERROR(NULL == pstSecuredRACertRequest, 
                     SecuredRACertRequest_t, 
                     "calloc failed\n");
    
    // Field: protocolVersion
    pstSecuredRACertRequest->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_unsecuredData;
    /** 透明指针 - ScopedEeRaCertRequest  */
    ScopedEeRaCertRequest_t* pstScopedEeRaCertRequest = NULL;
    pstScopedEeRaCertRequest = calloc(1, sizeof(ScopedEeRaCertRequest_t));
    STOP_IT_IF_ERROR(NULL == pstScopedEeRaCertRequest, 
                     ScopedEeRaCertRequest_t, 
                     "calloc failed\n");
    
    pstScopedEeRaCertRequest->version = ScmsPDUVersion;
    pstScopedEeRaCertRequest->content.present = ScmsPDU__content_PR_ee_ra;
    pstScopedEeRaCertRequest->content.choice.ee_ra
                    .present = EndEntityRaInterfacePDU_PR_eeRaCertRequest;
    pstScopedEeRaCertRequest->content.choice.ee_ra
                    .choice.eeRaCertRequest
                        .version = EeRaCertReqVersion;
    
    char oerbuf[OERBUFSIZE] = { 0 };
    size_t oerlen = 0;
    asn_enc_rval_t ec = oer_encode_to_buffer(&asn_DEF_ScopedEeRaCertRequest,
                                             NULL,
                                             pstScopedEeRaCertRequest,
                                             oerbuf,
                                             OERBUFSIZE);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode_to_buffer,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    oerlen = ec.encoded;

    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.unsecuredData,
            oerbuf,
            oerlen,
            ret);
    STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");
    
    pstSecuredRACertRequest->content = pstIeee1609Dot2Content;
    
    /** 测试 */
    FILE *fp = fopen("SecuredRACertRequest.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_SecuredRACertRequest,
                                     pstSecuredRACertRequest,
                                     write_callback,
                                     (void*)fp);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
                     
    if (fp) fclose(fp);
    fp = fopen("ScopedEeRaCertRequest.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_ScopedEeRaCertRequest,
                    pstScopedEeRaCertRequest,
                    write_callback,
                    (void*)fp);
    // xml print SecuredRACertRequest_t
    xer_fprint(stdout, &asn_DEF_SecuredRACertRequest, pstSecuredRACertRequest);
    // xml print ScopedEeRaCertRequest_t
    xer_fprint(stdout, &asn_DEF_ScopedEeRaCertRequest, pstScopedEeRaCertRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode ra request success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SecuredRACertRequest, pstSecuredRACertRequest);
    ASN_STRUCT_FREE(asn_DEF_ScopedEeRaCertRequest, pstScopedEeRaCertRequest);
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free ra request success ====\n");
    
    return ret;
}

int decode_SecuredRACertRequest(const unsigned char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SecuredRACertRequest_t* pstSecuredRACertRequest = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SecuredRACertRequest, 
                      (void**)&pstSecuredRACertRequest,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SecuredRACertRequest, pstSecuredRACertRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SecuredRACertRequest_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SecuredRACertRequest, pstSecuredRACertRequest);
    if (0 == ret) fprintf(stdout, "==== free SecuredRACertRequest_t success ====\n");
    
    return ret;
}

int decode_ScopedEeRaCertRequest(const unsigned char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    ScopedEeRaCertRequest_t* pstScopedEeRaCertRequest = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_ScopedEeRaCertRequest, 
                      (void**)&pstScopedEeRaCertRequest,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_ScopedEeRaCertRequest, pstScopedEeRaCertRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode ScopedEeRaCertRequest_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_ScopedEeRaCertRequest, pstScopedEeRaCertRequest);
    if (0 == ret) fprintf(stdout, "==== free ScopedEeRaCertRequest_t success ====\n");
    
    return ret;
}

int encode_SecuredRACertResponse()
{
    int ret = -1;
    
    int flag_ScopedElectorEndorsement = 1;
    int flag_CrlContents = 1;
    
    SecuredRACertResponse_t* pstSecuredRACertResponse = NULL;
    
    pstSecuredRACertResponse = calloc(1, sizeof(SecuredRACertResponse_t));
    STOP_IT_IF_ERROR(NULL == pstSecuredRACertResponse, 
                     SecuredRACertResponse_t, 
                     "calloc failed\n");
    // Field: protocolVersion
    pstSecuredRACertResponse->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_unsecuredData;
    /** 不透明指针 - ScopedRaEeCertResponse */
    ScopedRaEeCertResponse_t* pstScopedRaEeCertResponse = NULL;
    pstScopedRaEeCertResponse = calloc(1, sizeof(ScopedRaEeCertResponse_t));
    STOP_IT_IF_ERROR(NULL == pstScopedRaEeCertResponse, 
                     ScopedRaEeCertResponse_t, 
                     "calloc failed\n");
    
    pstScopedRaEeCertResponse->version = ScmsPDUVersion;
    pstScopedRaEeCertResponse->content.present = ScmsPDU__content_PR_ee_ra;
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .present = EndEntityRaInterfacePDU_PR_raEeCertResponse;
                        
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse
                            .version = EeRaCertResVersion;
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .present = RaEeCertResponseMsg__reply_PR_ack;
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .version = CertificateVersion;
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .type = CertificateType_implicit;
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .issuer.present = IssuerIdentifier_PR_self; // 分界线 begin
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .issuer.choice.self = HashAlgorithm_sm3;
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .toBeSigned.id
                                    .present = CertificateId_PR_none;
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .toBeSigned.id
                                    .choice.none = 0;
    FILL_WITH_OCTET_STRING(
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .toBeSigned
                                    .cracaId, ucs, 3, ret);
    STOP_IT_IF_ERROR(0 != ret, HashedId3_t, "OCTET_STRING_fromBuf failed\n");           
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .toBeSigned
                                    .crlSeries = 65512;
    
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .toBeSigned
                                    .validityPeriod.start = time(NULL);
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .toBeSigned
                                    .validityPeriod.duration
                                        .present = Duration_PR_years;
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .toBeSigned
                                    .validityPeriod.duration
                                        .choice.years = 15;

    struct SequenceOfPsidSsp* pstAppPermissions = NULL;
    pstAppPermissions = calloc(1, sizeof(struct SequenceOfPsidSsp));
    STOP_IT_IF_ERROR(NULL == pstAppPermissions,
                     SequenceOfPsidSsp_t,
                     "calloc failed\n");
    
    struct PsidSsp* parrPsidSsp[XSIZE] = { NULL };
    int i;
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrPsidSsp[i]) {
            parrPsidSsp[i] = calloc(1, sizeof(struct PsidSsp));
            STOP_IT_IF_ERROR(NULL == parrPsidSsp[i], PsidSsp_t, "calloc failed\n");
        }
        parrPsidSsp[i]->psid = 100;
        parrPsidSsp[i]->ssp = calloc(1, sizeof(struct ServiceSpecificPermissions));
        STOP_IT_IF_ERROR(NULL == parrPsidSsp[i]->ssp,
                         ServiceSpecificPermissions_t,
                         "calloc failed\n");
        parrPsidSsp[i]->ssp->present = ServiceSpecificPermissions_PR_opaque;
        FILL_WITH_OCTET_STRING(parrPsidSsp[i]->ssp->choice.opaque, ucs, -1, ret);
        STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        ret = asn_set_add(&pstAppPermissions->list, parrPsidSsp[i]);
        STOP_IT_IF_ERROR(0 != ret, ServiceSpecificPermissions_t, "asn_set_add failed\n");
    }
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .toBeSigned
                                    .appPermissions = pstAppPermissions;

    struct SequenceOfPsidGroupPermissions* pstCertIssuePermissions = NULL;
    pstCertIssuePermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
    STOP_IT_IF_ERROR(NULL == pstCertIssuePermissions, 
                     SequenceOfPsidGroupPermissions_t, 
                     "calloc failed\n");
    struct PsidGroupPermissions* parrCertIssuePermissions[XSIZE] = { NULL };
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrCertIssuePermissions[i]) {
            parrCertIssuePermissions[i] = calloc(1, sizeof(struct PsidGroupPermissions));
            STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[i], 
                             PsidGroupPermissions_t,
                             "calloc failed\n");
        }
        parrCertIssuePermissions[i]->subjectPermissions.present = SubjectPermissions_PR_all;
        parrCertIssuePermissions[i]->subjectPermissions.choice.all = 0;
        
        if (NULL == parrCertIssuePermissions[i]->minChainLength) {
            parrCertIssuePermissions[i]->minChainLength = calloc(1, sizeof(long));
            STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[i]->minChainLength, 
                             long_t,
                             "calloc failed\n");
        }
        *parrCertIssuePermissions[i]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
        
        parrCertIssuePermissions[i]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
        
        if (NULL == parrCertIssuePermissions[i]->eeType) {
            parrCertIssuePermissions[i]->eeType = calloc(1, sizeof(EndEntityType_t));
            STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[i]->eeType, 
                             EndEntityType_t,
                             "calloc failed\n");
        }
        if (NULL == parrCertIssuePermissions[i]->eeType->buf) {
            parrCertIssuePermissions[i]->eeType->buf = calloc(1, 1);
            STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[i]->eeType->buf, 
                             uint8_t,
                             "calloc failed\n");
        }
        parrCertIssuePermissions[i]->eeType->size = 1;
        parrCertIssuePermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
        parrCertIssuePermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
        parrCertIssuePermissions[i]->eeType->bits_unused = 6;
        
        ret = asn_set_add(&pstCertIssuePermissions->list, parrCertIssuePermissions[i]);
        STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
    }                               
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .toBeSigned
                                    .certIssuePermissions = pstCertIssuePermissions;

    struct SequenceOfPsidGroupPermissions* pstCertRequestPermissions = NULL;
    pstCertRequestPermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
    STOP_IT_IF_ERROR(NULL == pstCertRequestPermissions, 
                     SequenceOfPsidGroupPermissions_t, 
                     "calloc failed\n");
    struct PsidGroupPermissions* parrCertRequestPermissions[XSIZE] = { NULL };
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrCertRequestPermissions[i]) {
            parrCertRequestPermissions[i] = calloc(1, sizeof(struct PsidGroupPermissions));
            STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[i], 
                             PsidGroupPermissions_t,
                             "calloc failed\n");
        }
        parrCertRequestPermissions[i]->subjectPermissions.present = SubjectPermissions_PR_all;
        parrCertRequestPermissions[i]->subjectPermissions.choice.all = 0;
        
        if (NULL == parrCertRequestPermissions[i]->minChainLength) {
            parrCertRequestPermissions[i]->minChainLength = calloc(1, sizeof(long));
            STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[i]->minChainLength, 
                             long_t,
                             "calloc failed\n");
        }
        *parrCertRequestPermissions[i]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
        
        parrCertRequestPermissions[i]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
        
        if (NULL == parrCertRequestPermissions[i]->eeType) {
            parrCertRequestPermissions[i]->eeType = calloc(1, sizeof(EndEntityType_t));
            STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[i]->eeType, 
                             EndEntityType_t,
                             "calloc failed\n");
        }
        if (NULL == parrCertRequestPermissions[i]->eeType->buf) {
            parrCertRequestPermissions[i]->eeType->buf = calloc(1, 1);
            STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[i]->eeType->buf, 
                             uint8_t,
                             "calloc failed\n");
        }
        parrCertRequestPermissions[i]->eeType->size = 1;
        parrCertRequestPermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
        parrCertRequestPermissions[i]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
        parrCertRequestPermissions[i]->eeType->bits_unused = 6;
        
        ret = asn_set_add(&pstCertRequestPermissions->list, parrCertRequestPermissions[i]);
        STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
    }
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .toBeSigned
                                    .certRequestPermissions = pstCertRequestPermissions;

    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .toBeSigned
                                    .verifyKeyIndicator
                                        .present = VerificationKeyIndicator_PR_reconstructionValue;
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .toBeSigned
                                    .verifyKeyIndicator
                                        .choice.reconstructionValue
                                            .present = EccP256CurvePoint_PR_x_only;
    FILL_WITH_OCTET_STRING(
    pstScopedRaEeCertResponse->content.choice.ee_ra
                        .choice.raEeCertResponse.reply
                            .choice.ack.raCertificate
                                .toBeSigned
                                    .verifyKeyIndicator
                                        .choice.reconstructionValue
                                            .choice.x_only, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");    // 分界线 end
    
    SecuredCrl_t* pstSecuredCrl[XSIZE] = { NULL };
    for (i = 0; i < XSIZE; i++) {
        if (NULL == pstSecuredCrl[i]) {
            pstSecuredCrl[i] = calloc(1, sizeof(SecuredCrl_t));
            STOP_IT_IF_ERROR(NULL == pstSecuredCrl[i], 
                             SecuredCrl_t,
                             "calloc failed\n");
        }
        pstSecuredCrl[i]->protocolVersion = ProtocolVersion;
        
        struct Ieee1609Dot2Content* pstContent = NULL;
        pstContent = calloc(1, sizeof(struct Ieee1609Dot2Content));
        STOP_IT_IF_ERROR(NULL == pstContent, 
                         Ieee1609Dot2Content_t,
                         "calloc failed\n");
                         
        pstContent->present = Ieee1609Dot2Content_PR_signedData;
        
        struct SignedData* pstSignedData = NULL;
        pstSignedData = calloc(1, sizeof(struct SignedData));
        STOP_IT_IF_ERROR(NULL == pstSignedData, 
                         SignedData_t, 
                         "calloc failed\n");
        
        pstSignedData->hashId = HashAlgorithm_sm3;
        
        struct ToBeSignedData* pstToBeSignedData = NULL;
        pstToBeSignedData = calloc(1, sizeof(struct ToBeSignedData));
        STOP_IT_IF_ERROR(NULL == pstToBeSignedData, 
                         ToBeSignedData_t, 
                         "calloc failed\n");
        
        struct SignedDataPayload* pstSignedDataPayload = NULL;
        pstSignedDataPayload = calloc(1, sizeof(struct SignedDataPayload));
        STOP_IT_IF_ERROR(NULL == pstSignedDataPayload, 
                         SignedDataPayload_t, 
                         "calloc failed\n");
        
        struct Ieee1609Dot2Data* pstIeee1609Dot2Data = NULL;
        pstIeee1609Dot2Data = calloc(1, sizeof(struct Ieee1609Dot2Data));
        STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Data, 
                         Ieee1609Dot2Data_t, 
                         "calloc failed\n");
        
        pstIeee1609Dot2Data->protocolVersion = ProtocolVersion;
        
        struct Ieee1609Dot2Content* pstIeee1609Dot2ContentUnsecuredData = NULL;
        pstIeee1609Dot2ContentUnsecuredData = calloc(1, sizeof(struct Ieee1609Dot2Content));
        STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2ContentUnsecuredData, 
                         Ieee1609Dot2Content_t, 
                         "calloc failed\n");
        pstIeee1609Dot2ContentUnsecuredData->present = Ieee1609Dot2Content_PR_unsecuredData;
        /** 不透明指针 - CrlContents */
        struct CrlContents* pstCrlContents = NULL;
        pstCrlContents = calloc(1, sizeof(struct CrlContents));
        STOP_IT_IF_ERROR(NULL == pstCrlContents, 
                         CrlContents_t, 
                         "calloc failed\n");
        pstCrlContents->version = CrlContentVersion;
        pstCrlContents->crlSeries = 65512;
        FILL_WITH_OCTET_STRING(
        pstCrlContents->cracaId, ucs, 8, ret);
        STOP_IT_IF_ERROR(0 != ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
        pstCrlContents->issueDate = time(NULL);
        pstCrlContents->nextCrl = time(NULL) + 1234;
        pstCrlContents->priorityInfo.priority = NULL;               // 异常可能出现的地方
        
        pstCrlContents->typeSpecific.present = CrlContents__typeSpecific_PR_fullHashCrl;
        pstCrlContents->typeSpecific.choice.fullHashCrl.crlSerial = 0x4567;
        
        int j;
        struct HashBasedRevocationInfo* parrHashBasedRevocationInfo[YSIZE] = { NULL };
        for (j = 0; j < YSIZE; j++) {
            if (NULL == parrHashBasedRevocationInfo[j]) {
                parrHashBasedRevocationInfo[j] = calloc(1, sizeof(struct PsidGroupPermissions));
                STOP_IT_IF_ERROR(NULL == parrHashBasedRevocationInfo[j], 
                                 HashBasedRevocationInfo_t,
                                 "calloc failed\n");
            }
            FILL_WITH_OCTET_STRING(
            parrHashBasedRevocationInfo[j]->id, ucs, 10, ret);
            STOP_IT_IF_ERROR(0 != ret, HashedId10_t, "OCTET_STRING_fromBuf failed\n");
            parrHashBasedRevocationInfo[j]->expiry = time(NULL) + 0x987;
            
            ret = asn_set_add(
                    &pstCrlContents->typeSpecific.choice.fullHashCrl.entries.list,
                    parrHashBasedRevocationInfo[j]);
            STOP_IT_IF_ERROR(0 != ret, HashBasedRevocationInfo_t, "asn_set_add failed\n");
        }
        
        char oerbuf[OERBUFSIZE] = { 0 };
        size_t oerlen = 0;
        asn_enc_rval_t ec = oer_encode_to_buffer(&asn_DEF_CrlContents,
                                                 NULL,
                                                 pstCrlContents,
                                                 oerbuf,
                                                 OERBUFSIZE);
        STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode_to_buffer,
                         "%d ecode(%d): %s\n", 
                         __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
        
        oerlen = ec.encoded;
            
        FILL_WITH_OCTET_STRING(
        pstIeee1609Dot2ContentUnsecuredData->choice.unsecuredData,
                oerbuf,
                oerlen,
                ret);
        STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");
        
        pstIeee1609Dot2Data->content = pstIeee1609Dot2ContentUnsecuredData;
        
        pstSignedDataPayload->data = pstIeee1609Dot2Data;
        
        // pstSignedDataPayload->extDataHash = ... // do noting
        
        pstToBeSignedData->payload = pstSignedDataPayload;
        
        pstToBeSignedData->headerInfo.psid = CrlPsidValue;
        
        // DO NOTHING: HeaderInfo others
        
        pstSignedData->tbsData = pstToBeSignedData;
        
        pstSignedData->signer.present = SignerIdentifier_PR_self;
        pstSignedData->signer.choice.self = 0;
        
        pstSignedData->signature
                        .present = Signature_PR_sm2Signature;
        
        FILL_WITH_OCTET_STRING(
        pstSignedData->signature
                        .choice.sm2Signature.r, ucs, 32, ret);
        STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        
        FILL_WITH_OCTET_STRING(
        pstSignedData->signature
                        .choice.sm2Signature.s, ucs, 32, ret);
        STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        
        pstContent->choice.signedData = pstSignedData;
        
        pstSecuredCrl[i]->content = pstContent;
        
        ret = asn_set_add(
        &pstScopedRaEeCertResponse->content.choice.ee_ra
                                .choice.raEeCertResponse.reply
                                    .choice.ack
                                        .crl.securedCrlSeries
                                            .list, pstSecuredCrl[i]);
        STOP_IT_IF_ERROR(0 != ret, CompositeCrl__securedCrlSeries, "asn_set_add failed\n");
        
        if (flag_CrlContents == 1) {
            FILE *fp = fopen("CrlContents.coer", "wb");
            STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
            
            asn_enc_rval_t ec = oer_encode(&asn_DEF_CrlContents,
                                             pstCrlContents,
                                             write_callback,
                                             (void*)fp);
            STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                             "%d ecode(%d): %s\n", 
                             __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
                             
            if (fp) fclose(fp);
            
            flag_CrlContents = 0;
        }
        
        ASN_STRUCT_FREE(asn_DEF_CrlContents, pstCrlContents);
    }
    
    struct ElectorBallot* pstRevokedRootCAs[XSIZE] = { NULL };
    for (i = 0; i < XSIZE; i++) {
        if (NULL == pstRevokedRootCAs[i]) {
            pstRevokedRootCAs[i] = calloc(1, sizeof(struct ElectorBallot));
            STOP_IT_IF_ERROR(NULL == pstRevokedRootCAs[i], 
                             ElectorBallot_t,
                             "calloc failed\n");
        }
        
        SignedElectorEndorsement_t* pstSignedElectorEndorsement[YSIZE] = { NULL };
        int j;
        for (j = 0; j < YSIZE; j++) {
            if (NULL == pstSignedElectorEndorsement[j]) {
                pstSignedElectorEndorsement[j] = calloc(1, sizeof(SignedElectorEndorsement_t));
                STOP_IT_IF_ERROR(NULL == pstSignedElectorEndorsement[j], 
                                 SignedElectorEndorsement_t,
                                 "calloc failed\n");
            }
            pstSignedElectorEndorsement[j]->protocolVersion = ProtocolVersion;
            
            struct Ieee1609Dot2Content* pstSubContent = NULL;
            pstSubContent = calloc(1, sizeof(struct Ieee1609Dot2Content));
            STOP_IT_IF_ERROR(NULL == pstSubContent, 
                             pstSubContent_t,
                             "calloc failed\n");
            pstSubContent->present = Ieee1609Dot2Content_PR_signedData;
            
            struct SignedData* pstSignedData = NULL;
            pstSignedData = calloc(1, sizeof(struct SignedData));
            STOP_IT_IF_ERROR(NULL == pstSignedData, 
                             SignedData_t, 
                             "calloc failed\n");        
            pstSignedData->hashId = HashAlgorithm_sm3;
            
            struct ToBeSignedData* pstToBeSignedData = NULL;
            pstToBeSignedData = calloc(1, sizeof(struct ToBeSignedData));
            STOP_IT_IF_ERROR(NULL == pstToBeSignedData, 
                             ToBeSignedData_t, 
                             "calloc failed\n");
            
            struct SignedDataPayload* pstSignedDataPayload = NULL;
            pstSignedDataPayload = calloc(1, sizeof(struct SignedDataPayload));
            STOP_IT_IF_ERROR(NULL == pstSignedDataPayload, 
                             SignedDataPayload_t, 
                             "calloc failed\n");
            
            struct Ieee1609Dot2Data* pstSubIeee1609Dot2Data = NULL;
            pstSubIeee1609Dot2Data = calloc(1, sizeof(struct Ieee1609Dot2Data));
            STOP_IT_IF_ERROR(NULL == pstSubIeee1609Dot2Data, 
                             Ieee1609Dot2Data_t,
                             "calloc failed\n");
            pstSubIeee1609Dot2Data->protocolVersion = ProtocolVersion;
            
            
            struct Ieee1609Dot2Content* pstAnotherContent = NULL;
            pstAnotherContent = calloc(1, sizeof(struct Ieee1609Dot2Content));
            STOP_IT_IF_ERROR(NULL == pstAnotherContent, 
                             Ieee1609Dot2Content_t,
                             "calloc failed\n");
            
            pstAnotherContent->present = Ieee1609Dot2Content_PR_unsecuredData;
            
            /** 不透明指针 - ScopedElectorEndorsement */
            ScopedElectorEndorsement_t* pstScopedElectorEndorsement = NULL;
            pstScopedElectorEndorsement = calloc(1, sizeof(ScopedElectorEndorsement_t));
            STOP_IT_IF_ERROR(NULL == pstScopedElectorEndorsement, 
                             pstScopedElectorEndorsement_t,
                             "calloc failed\n");
            
            pstScopedElectorEndorsement->version = ScmsPDUVersion;
            pstScopedElectorEndorsement->content.present = ScmsPDU__content_PR_ccm;
            
            pstScopedElectorEndorsement->content.choice.ccm
                            .present = ScmsComponentCertificateManagementPDU_PR_tbsElectorEndorsement;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .type = EndorsementType_addElector;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .version = CertificateVersion;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .type = CertificateType_explicit;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .issuer.present = IssuerIdentifier_PR_self;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .issuer.choice.self = HashAlgorithm_sm3;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned.id
                                        .present = CertificateId_PR_none;   // 分界线 begin
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned.id
                                        .choice.none = 0;   
            FILL_WITH_OCTET_STRING(
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned.cracaId, ucs, 3, ret);
            STOP_IT_IF_ERROR(0 != ret, HashedId3_t, "OCTET_STRING_fromBuf failed\n");
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .crlSeries = 65513;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .validityPeriod.start = time(NULL);

            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .validityPeriod.duration
                                            .present = Duration_PR_years;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .validityPeriod.duration
                                            .choice.years = 16;
            
            struct SequenceOfPsidSsp* pstSubAppPermissions = NULL;
            pstSubAppPermissions = calloc(1, sizeof(struct SequenceOfPsidSsp));
            STOP_IT_IF_ERROR(NULL == pstSubAppPermissions,
                             SequenceOfPsidSsp_t,
                             "calloc failed\n");
            
            struct PsidSsp* parrSubPsidSsp[XSIZE] = { NULL };
            int k;
            for (k = 0; k < XSIZE; k++) {
                if (NULL == parrSubPsidSsp[k]) {
                    parrSubPsidSsp[k] = calloc(1, sizeof(struct PsidSsp));
                    STOP_IT_IF_ERROR(NULL == parrSubPsidSsp[k], PsidSsp_t, "calloc failed\n");
                }
                parrSubPsidSsp[k]->psid = 100;
                parrSubPsidSsp[k]->ssp = calloc(1, sizeof(struct ServiceSpecificPermissions));
                STOP_IT_IF_ERROR(NULL == parrSubPsidSsp[k]->ssp,
                                 ServiceSpecificPermissions_t,
                                 "calloc failed\n");
                parrSubPsidSsp[k]->ssp->present = ServiceSpecificPermissions_PR_opaque;
                FILL_WITH_OCTET_STRING(parrSubPsidSsp[k]->ssp->choice.opaque, ucs, -1, ret);
                STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                ret = asn_set_add(&pstSubAppPermissions->list, parrSubPsidSsp[k]);
                STOP_IT_IF_ERROR(0 != ret, ServiceSpecificPermissions_t, "asn_set_add failed\n");
            }
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .appPermissions = pstSubAppPermissions;
                                        
            struct SequenceOfPsidGroupPermissions* pstSubCertIssuePermissions = NULL;
            pstSubCertIssuePermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
            STOP_IT_IF_ERROR(NULL == pstSubCertIssuePermissions, 
                             SequenceOfPsidGroupPermissions_t, 
                             "calloc failed\n");
            struct PsidGroupPermissions* parrSubCertIssuePermissions[XSIZE] = { NULL };
            for (k = 0; k < XSIZE; k++) {
                if (NULL == parrSubCertIssuePermissions[k]) {
                    parrSubCertIssuePermissions[k] = calloc(1, sizeof(struct PsidGroupPermissions));
                    STOP_IT_IF_ERROR(NULL == parrSubCertIssuePermissions[k], 
                                     PsidGroupPermissions_t,
                                     "calloc failed\n");
                }
                parrSubCertIssuePermissions[k]->subjectPermissions.present = SubjectPermissions_PR_all;
                parrSubCertIssuePermissions[k]->subjectPermissions.choice.all = 0;
                
                if (NULL == parrSubCertIssuePermissions[k]->minChainLength) {
                    parrSubCertIssuePermissions[k]->minChainLength = calloc(1, sizeof(long));
                    STOP_IT_IF_ERROR(NULL == parrSubCertIssuePermissions[k]->minChainLength, 
                                     long_t,
                                     "calloc failed\n");
                }
                *parrSubCertIssuePermissions[k]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
                
                parrSubCertIssuePermissions[k]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
                
                if (NULL == parrSubCertIssuePermissions[k]->eeType) {
                    parrSubCertIssuePermissions[k]->eeType = calloc(1, sizeof(EndEntityType_t));
                    STOP_IT_IF_ERROR(NULL == parrSubCertIssuePermissions[k]->eeType, 
                                     EndEntityType_t,
                                     "calloc failed\n");
                }
                if (NULL == parrSubCertIssuePermissions[k]->eeType->buf) {
                    parrSubCertIssuePermissions[k]->eeType->buf = calloc(1, 1);
                    STOP_IT_IF_ERROR(NULL == parrSubCertIssuePermissions[k]->eeType->buf, 
                                     uint8_t,
                                     "calloc failed\n");
                }
                parrSubCertIssuePermissions[k]->eeType->size = 1;
                parrSubCertIssuePermissions[k]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
                parrSubCertIssuePermissions[k]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
                parrSubCertIssuePermissions[k]->eeType->bits_unused = 6;
                
                ret = asn_set_add(&pstSubCertIssuePermissions->list, parrSubCertIssuePermissions[k]);
                STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
            }
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .certIssuePermissions = pstSubCertIssuePermissions;

            struct SequenceOfPsidGroupPermissions* pstSubCertRequestPermissions = NULL;
            pstSubCertRequestPermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
            STOP_IT_IF_ERROR(NULL == pstSubCertRequestPermissions, 
                             SequenceOfPsidGroupPermissions_t, 
                             "calloc failed\n");
            struct PsidGroupPermissions* parrSubCertRequestPermissions[XSIZE] = { NULL };
            for (k = 0; k < XSIZE; k++) {
                if (NULL == parrSubCertRequestPermissions[k]) {
                    parrSubCertRequestPermissions[k] = calloc(1, sizeof(struct PsidGroupPermissions));
                    STOP_IT_IF_ERROR(NULL == parrSubCertRequestPermissions[k], 
                                     PsidGroupPermissions_t,
                                     "calloc failed\n");
                }
                parrSubCertRequestPermissions[k]->subjectPermissions.present = SubjectPermissions_PR_all;
                parrSubCertRequestPermissions[k]->subjectPermissions.choice.all = 0;
                
                if (NULL == parrSubCertRequestPermissions[k]->minChainLength) {
                    parrSubCertRequestPermissions[k]->minChainLength = calloc(1, sizeof(long));
                    STOP_IT_IF_ERROR(NULL == parrSubCertRequestPermissions[k]->minChainLength, 
                                     long_t,
                                     "calloc failed\n");
                }
                *parrSubCertRequestPermissions[k]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
                
                parrSubCertRequestPermissions[k]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
                
                if (NULL == parrSubCertRequestPermissions[k]->eeType) {
                    parrSubCertRequestPermissions[k]->eeType = calloc(1, sizeof(EndEntityType_t));
                    STOP_IT_IF_ERROR(NULL == parrSubCertRequestPermissions[k]->eeType, 
                                     EndEntityType_t,
                                     "calloc failed\n");
                }
                if (NULL == parrSubCertRequestPermissions[k]->eeType->buf) {
                    parrSubCertRequestPermissions[k]->eeType->buf = calloc(1, 1);
                    STOP_IT_IF_ERROR(NULL == parrSubCertRequestPermissions[k]->eeType->buf, 
                                     uint8_t,
                                     "calloc failed\n");
                }
                parrSubCertRequestPermissions[k]->eeType->size = 1;
                parrSubCertRequestPermissions[k]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
                parrSubCertRequestPermissions[k]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
                parrSubCertRequestPermissions[k]->eeType->bits_unused = 6;
                
                ret = asn_set_add(&pstSubCertRequestPermissions->list, parrSubCertRequestPermissions[k]);
                STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
            }
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .certRequestPermissions = pstSubCertRequestPermissions;

            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .verifyKeyIndicator
                                            .present = VerificationKeyIndicator_PR_verificationKey;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .verifyKeyIndicator
                                            .choice.verificationKey
                                                .present = PublicVerificationKey_PR_ecsigSm2;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .verifyKeyIndicator
                                            .choice.verificationKey
                                                .choice.ecsigSm2
                                                    .present = EccP256CurvePoint_PR_x_only;
            FILL_WITH_OCTET_STRING(                                     
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .verifyKeyIndicator
                                            .choice.verificationKey                                         
                                                .choice.ecsigSm2
                                                    .choice.x_only, ucs, 32, ret);
            STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");

            struct Signature* pstSignature = NULL;
            pstSignature = calloc(1, sizeof(struct Signature));
            STOP_IT_IF_ERROR(NULL == pstSignature,
                             Signature_t,
                             "calloc failed\n");
            pstSignature->present = Signature_PR_sm2Signature;
            FILL_WITH_OCTET_STRING(
            pstSignature->choice
                            .sm2Signature.r, ucs, 32, ret);
            STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            FILL_WITH_OCTET_STRING(
            pstSignature->choice
                            .sm2Signature.s, ucs, 32, ret);
            STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .signature = pstSignature;
        
            // pstScopedElectorEndorsement->content.choice.ccm
                            // .choice.tbsElectorEndorsement
                                // .certificate
                                    // .effectiveTime = ... // do nothing

            char oerbuf[OERBUFSIZE] = { 0 };
            size_t oerlen = 0;
            asn_enc_rval_t ec = oer_encode_to_buffer(&asn_DEF_ScopedElectorEndorsement,
                                                     NULL,
                                                     pstScopedElectorEndorsement,
                                                     oerbuf,
                                                     OERBUFSIZE);
            STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode_to_buffer,
                             "%d ecode(%d): %s\n", 
                             __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
            
            oerlen = ec.encoded;
                
            FILL_WITH_OCTET_STRING(
            pstAnotherContent->choice.unsecuredData,
                    oerbuf,
                    oerlen,
                    ret);
            STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");
            
            pstSubIeee1609Dot2Data->content = pstAnotherContent;
            
            pstSignedDataPayload->data = pstSubIeee1609Dot2Data;
            // pstSignedDataPayload->extDataHash = .. // do nothing
            
            pstToBeSignedData->payload = pstSignedDataPayload;
            
            pstToBeSignedData->headerInfo
                            .psid = PsidValue;
            
            pstToBeSignedData->headerInfo.generationTime = calloc(1, sizeof(Time64_t));
            STOP_IT_IF_ERROR(NULL == pstToBeSignedData->headerInfo.generationTime, 
                             Time64_t, 
                             "calloc failed\n");
            ret = asn_ulong2INTEGER(pstToBeSignedData->headerInfo.generationTime, time(NULL));
            STOP_IT_IF_ERROR(0 != ret, Time64_t, "asn_ulong2INTEGER failed\n");
            
            // ABSENT: expiryTime, generationLocation, p2pcdLearningRequest, missingCrlIdentifier
            //         encryptionKey
            // DO NOTHING: inlineP2pcdRequest, requestedCertificate, pduFunctionalType          
            
            pstSignedData->tbsData = pstToBeSignedData;
            
            pstSignedData->signer
                            .present = SignerIdentifier_PR_self;
            pstSignedData->signer
                            .choice.self = 0;
                            
            pstSignedData->signature
                            .present = Signature_PR_sm2Signature;
            FILL_WITH_OCTET_STRING(             
            pstSignedData->signature
                            .choice.sm2Signature.r, ucs, 32, ret);
            STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            FILL_WITH_OCTET_STRING(
            pstSignedData->signature
                            .choice.sm2Signature.s, ucs, 32, ret);
            STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                
            pstSubContent->choice.signedData = pstSignedData;
            
            pstSignedElectorEndorsement[j]->content = pstSubContent;
            
            ret = asn_set_add(
            &pstRevokedRootCAs[i]->endorsements.list, pstSignedElectorEndorsement[j]);
            STOP_IT_IF_ERROR(0 != ret, SignedElectorEndorsement_t, "asn_set_add failed\n");
            
            if (flag_ScopedElectorEndorsement == 1) {
                FILE *fp = fopen("ScopedElectorEndorsement.coer", "wb");
                STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
                
                asn_enc_rval_t ec = oer_encode(&asn_DEF_ScopedElectorEndorsement,
                                                 pstScopedElectorEndorsement,
                                                 write_callback,
                                                 (void*)fp);
                STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                                 "%d ecode(%d): %s\n", 
                                 __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
                                 
                if (fp) fclose(fp);
                
                flag_ScopedElectorEndorsement = 0;
            }
            
            ASN_STRUCT_FREE(asn_DEF_ScopedElectorEndorsement, pstScopedElectorEndorsement);
        }
                
        ret = asn_set_add(
        &pstScopedRaEeCertResponse->content.choice.ee_ra
                                .choice.raEeCertResponse.reply
                                    .choice.ack
                                        .crl.revokedRootCAs
                                            .list, pstRevokedRootCAs[i]);
        STOP_IT_IF_ERROR(0 != ret, CompositeCrl__revokedRootCAs, "asn_set_add failed\n");
    }
    
    struct ElectorBallot* pstRevokedElectors[XSIZE] = { NULL };
    for (i = 0; i < XSIZE; i++) {
        if (NULL == pstRevokedElectors[i]) {
            pstRevokedElectors[i] = calloc(1, sizeof(struct ElectorBallot));
            STOP_IT_IF_ERROR(NULL == pstRevokedElectors[i], 
                             ElectorBallot_t,
                             "calloc failed\n");
        }
        
        SignedElectorEndorsement_t* pstSignedElectorEndorsement[YSIZE] = { NULL };
        int j;
        for (j = 0; j < YSIZE; j++) {
            if (NULL == pstSignedElectorEndorsement[j]) {
                pstSignedElectorEndorsement[j] = calloc(1, sizeof(SignedElectorEndorsement_t));
                STOP_IT_IF_ERROR(NULL == pstSignedElectorEndorsement[j], 
                                 SignedElectorEndorsement_t,
                                 "calloc failed\n");
            }
            pstSignedElectorEndorsement[j]->protocolVersion = ProtocolVersion;
            
            struct Ieee1609Dot2Content* pstSubContent = NULL;
            pstSubContent = calloc(1, sizeof(struct Ieee1609Dot2Content));
            STOP_IT_IF_ERROR(NULL == pstSubContent, 
                             pstSubContent_t,
                             "calloc failed\n");
            pstSubContent->present = Ieee1609Dot2Content_PR_signedData;
            
            struct SignedData* pstSignedData = NULL;
            pstSignedData = calloc(1, sizeof(struct SignedData));
            STOP_IT_IF_ERROR(NULL == pstSignedData, 
                             SignedData_t, 
                             "calloc failed\n");        
            pstSignedData->hashId = HashAlgorithm_sm3;
            
            struct ToBeSignedData* pstToBeSignedData = NULL;
            pstToBeSignedData = calloc(1, sizeof(struct ToBeSignedData));
            STOP_IT_IF_ERROR(NULL == pstToBeSignedData, 
                             ToBeSignedData_t, 
                             "calloc failed\n");
            
            struct SignedDataPayload* pstSignedDataPayload = NULL;
            pstSignedDataPayload = calloc(1, sizeof(struct SignedDataPayload));
            STOP_IT_IF_ERROR(NULL == pstSignedDataPayload, 
                             SignedDataPayload_t, 
                             "calloc failed\n");
            
            struct Ieee1609Dot2Data* pstSubIeee1609Dot2Data = NULL;
            pstSubIeee1609Dot2Data = calloc(1, sizeof(struct Ieee1609Dot2Data));
            STOP_IT_IF_ERROR(NULL == pstSubIeee1609Dot2Data, 
                             Ieee1609Dot2Data_t,
                             "calloc failed\n");
            pstSubIeee1609Dot2Data->protocolVersion = ProtocolVersion;
            
            
            struct Ieee1609Dot2Content* pstAnotherContent = NULL;
            pstAnotherContent = calloc(1, sizeof(struct Ieee1609Dot2Content));
            STOP_IT_IF_ERROR(NULL == pstAnotherContent, 
                             Ieee1609Dot2Content_t,
                             "calloc failed\n");
            
            pstAnotherContent->present = Ieee1609Dot2Content_PR_unsecuredData;
            
            /** 不透明指针 - ScopedElectorEndorsement */
            ScopedElectorEndorsement_t* pstScopedElectorEndorsement = NULL;
            pstScopedElectorEndorsement = calloc(1, sizeof(ScopedElectorEndorsement_t));
            STOP_IT_IF_ERROR(NULL == pstScopedElectorEndorsement, 
                             pstScopedElectorEndorsement_t,
                             "calloc failed\n");
            
            pstScopedElectorEndorsement->version = ScmsPDUVersion;
            pstScopedElectorEndorsement->content.present = ScmsPDU__content_PR_ccm;
            
            pstScopedElectorEndorsement->content.choice.ccm
                            .present = ScmsComponentCertificateManagementPDU_PR_tbsElectorEndorsement;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .type = EndorsementType_addElector;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .version = CertificateVersion;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .type = CertificateType_explicit;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .issuer.present = IssuerIdentifier_PR_self;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .issuer.choice.self = HashAlgorithm_sm3;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned.id
                                        .present = CertificateId_PR_none;   // 分界线 begin
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned.id
                                        .choice.none = 0;   
            FILL_WITH_OCTET_STRING(
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned.cracaId, ucs, 3, ret);
            STOP_IT_IF_ERROR(0 != ret, HashedId3_t, "OCTET_STRING_fromBuf failed\n");
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .crlSeries = 65513;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .validityPeriod.start = time(NULL);
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .validityPeriod.duration
                                            .present = Duration_PR_years;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .validityPeriod.duration
                                            .choice.years = 16;
            
            struct SequenceOfPsidSsp* pstSubAppPermissions = NULL;
            pstSubAppPermissions = calloc(1, sizeof(struct SequenceOfPsidSsp));
            STOP_IT_IF_ERROR(NULL == pstSubAppPermissions,
                             SequenceOfPsidSsp_t,
                             "calloc failed\n");
            
            struct PsidSsp* parrSubPsidSsp[XSIZE] = { NULL };
            int k;
            for (k = 0; k < XSIZE; k++) {
                if (NULL == parrSubPsidSsp[k]) {
                    parrSubPsidSsp[k] = calloc(1, sizeof(struct PsidSsp));
                    STOP_IT_IF_ERROR(NULL == parrSubPsidSsp[k], PsidSsp_t, "calloc failed\n");
                }
                parrSubPsidSsp[k]->psid = 100;
                parrSubPsidSsp[k]->ssp = calloc(1, sizeof(struct ServiceSpecificPermissions));
                STOP_IT_IF_ERROR(NULL == parrSubPsidSsp[k]->ssp,
                                 ServiceSpecificPermissions_t,
                                 "calloc failed\n");
                parrSubPsidSsp[k]->ssp->present = ServiceSpecificPermissions_PR_opaque;
                FILL_WITH_OCTET_STRING(parrSubPsidSsp[k]->ssp->choice.opaque, ucs, -1, ret);
                STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                ret = asn_set_add(&pstSubAppPermissions->list, parrSubPsidSsp[k]);
                STOP_IT_IF_ERROR(0 != ret, ServiceSpecificPermissions_t, "asn_set_add failed\n");
            }
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .appPermissions = pstSubAppPermissions;
                                        
            struct SequenceOfPsidGroupPermissions* pstSubCertIssuePermissions = NULL;
            pstSubCertIssuePermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
            STOP_IT_IF_ERROR(NULL == pstSubCertIssuePermissions, 
                             SequenceOfPsidGroupPermissions_t, 
                             "calloc failed\n");
            struct PsidGroupPermissions* parrSubCertIssuePermissions[XSIZE] = { NULL };
            for (k = 0; k < XSIZE; k++) {
                if (NULL == parrSubCertIssuePermissions[k]) {
                    parrSubCertIssuePermissions[k] = calloc(1, sizeof(struct PsidGroupPermissions));
                    STOP_IT_IF_ERROR(NULL == parrSubCertIssuePermissions[k], 
                                     PsidGroupPermissions_t,
                                     "calloc failed\n");
                }
                parrSubCertIssuePermissions[k]->subjectPermissions.present = SubjectPermissions_PR_all;
                parrSubCertIssuePermissions[k]->subjectPermissions.choice.all = 0;
                
                if (NULL == parrSubCertIssuePermissions[k]->minChainLength) {
                    parrSubCertIssuePermissions[k]->minChainLength = calloc(1, sizeof(long));
                    STOP_IT_IF_ERROR(NULL == parrSubCertIssuePermissions[k]->minChainLength, 
                                     long_t,
                                     "calloc failed\n");
                }
                *parrSubCertIssuePermissions[k]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
                
                parrSubCertIssuePermissions[k]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
                
                if (NULL == parrSubCertIssuePermissions[k]->eeType) {
                    parrSubCertIssuePermissions[k]->eeType = calloc(1, sizeof(EndEntityType_t));
                    STOP_IT_IF_ERROR(NULL == parrSubCertIssuePermissions[k]->eeType, 
                                     EndEntityType_t,
                                     "calloc failed\n");
                }
                if (NULL == parrSubCertIssuePermissions[k]->eeType->buf) {
                    parrSubCertIssuePermissions[k]->eeType->buf = calloc(1, 1);
                    STOP_IT_IF_ERROR(NULL == parrSubCertIssuePermissions[k]->eeType->buf, 
                                     uint8_t,
                                     "calloc failed\n");
                }
                parrSubCertIssuePermissions[k]->eeType->size = 1;
                parrSubCertIssuePermissions[k]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
                parrSubCertIssuePermissions[k]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
                parrSubCertIssuePermissions[k]->eeType->bits_unused = 6;
                
                ret = asn_set_add(&pstSubCertIssuePermissions->list, parrSubCertIssuePermissions[k]);
                STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
            }
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .certIssuePermissions = pstSubCertIssuePermissions;

            struct SequenceOfPsidGroupPermissions* pstSubCertRequestPermissions = NULL;
            pstSubCertRequestPermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
            STOP_IT_IF_ERROR(NULL == pstSubCertRequestPermissions, 
                             SequenceOfPsidGroupPermissions_t, 
                             "calloc failed\n");
            struct PsidGroupPermissions* parrSubCertRequestPermissions[XSIZE] = { NULL };
            for (k = 0; k < XSIZE; k++) {
                if (NULL == parrSubCertRequestPermissions[k]) {
                    parrSubCertRequestPermissions[k] = calloc(1, sizeof(struct PsidGroupPermissions));
                    STOP_IT_IF_ERROR(NULL == parrSubCertRequestPermissions[k], 
                                     PsidGroupPermissions_t,
                                     "calloc failed\n");
                }
                parrSubCertRequestPermissions[k]->subjectPermissions.present = SubjectPermissions_PR_all;
                parrSubCertRequestPermissions[k]->subjectPermissions.choice.all = 0;
                
                if (NULL == parrSubCertRequestPermissions[k]->minChainLength) {
                    parrSubCertRequestPermissions[k]->minChainLength = calloc(1, sizeof(long));
                    STOP_IT_IF_ERROR(NULL == parrSubCertRequestPermissions[k]->minChainLength, 
                                     long_t,
                                     "calloc failed\n");
                }
                *parrSubCertRequestPermissions[k]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
                
                parrSubCertRequestPermissions[k]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
                
                if (NULL == parrSubCertRequestPermissions[k]->eeType) {
                    parrSubCertRequestPermissions[k]->eeType = calloc(1, sizeof(EndEntityType_t));
                    STOP_IT_IF_ERROR(NULL == parrSubCertRequestPermissions[k]->eeType, 
                                     EndEntityType_t,
                                     "calloc failed\n");
                }
                if (NULL == parrSubCertRequestPermissions[k]->eeType->buf) {
                    parrSubCertRequestPermissions[k]->eeType->buf = calloc(1, 1);
                    STOP_IT_IF_ERROR(NULL == parrSubCertRequestPermissions[k]->eeType->buf, 
                                     uint8_t,
                                     "calloc failed\n");
                }
                parrSubCertRequestPermissions[k]->eeType->size = 1;
                parrSubCertRequestPermissions[k]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
                parrSubCertRequestPermissions[k]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
                parrSubCertRequestPermissions[k]->eeType->bits_unused = 6;
                
                ret = asn_set_add(&pstSubCertRequestPermissions->list, parrSubCertRequestPermissions[k]);
                STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
            }
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .certRequestPermissions = pstSubCertRequestPermissions;

            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .verifyKeyIndicator
                                            .present = VerificationKeyIndicator_PR_verificationKey;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .verifyKeyIndicator
                                            .choice.verificationKey
                                                .present = PublicVerificationKey_PR_ecsigSm2;
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .verifyKeyIndicator
                                            .choice.verificationKey
                                                .choice.ecsigSm2
                                                    .present = EccP256CurvePoint_PR_x_only;
            FILL_WITH_OCTET_STRING(                                     
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .toBeSigned
                                        .verifyKeyIndicator
                                            .choice.verificationKey                                         
                                                .choice.ecsigSm2
                                                    .choice.x_only, ucs, 32, ret);
            STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");

            struct Signature* pstSignature = NULL;
            pstSignature = calloc(1, sizeof(struct Signature));
            STOP_IT_IF_ERROR(NULL == pstSignature,
                             Signature_t,
                             "calloc failed\n");
            pstSignature->present = Signature_PR_sm2Signature;
            FILL_WITH_OCTET_STRING(
            pstSignature->choice
                            .sm2Signature.r, ucs, 32, ret);
            STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            FILL_WITH_OCTET_STRING(
            pstSignature->choice
                            .sm2Signature.s, ucs, 32, ret);
            STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
            pstScopedElectorEndorsement->content.choice.ccm
                            .choice.tbsElectorEndorsement
                                .certificate
                                    .signature = pstSignature;
        
            // pstScopedElectorEndorsement->content.choice.ccm
                            // .choice.tbsElectorEndorsement
                                // .certificate
                                    // .effectiveTime = ... // do nothing

            char oerbuf[OERBUFSIZE] = { 0 };
            size_t oerlen = 0;
            asn_enc_rval_t ec = oer_encode_to_buffer(&asn_DEF_ScopedElectorEndorsement,
                                                     NULL,
                                                     pstScopedElectorEndorsement,
                                                     oerbuf,
                                                     OERBUFSIZE);
            STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode_to_buffer,
                             "%d ecode(%d): %s\n", 
                             __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
            
            oerlen = ec.encoded;
                
            FILL_WITH_OCTET_STRING(
            pstAnotherContent->choice.unsecuredData,
                    oerbuf,
                    oerlen,
                    ret);
            STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");

            pstSubIeee1609Dot2Data->content = pstAnotherContent;
            
            pstSignedDataPayload->data = pstSubIeee1609Dot2Data;
            // pstSignedDataPayload->extDataHash = .. // do nothing
            
            pstToBeSignedData->payload = pstSignedDataPayload;
            

            pstToBeSignedData->headerInfo
                            .psid = PsidValue;
                            
            pstToBeSignedData->headerInfo.generationTime = calloc(1, sizeof(Time64_t));
            STOP_IT_IF_ERROR(NULL == pstToBeSignedData->headerInfo.generationTime, 
                             Time64_t, 
                             "calloc failed\n");
            ret = asn_ulong2INTEGER(pstToBeSignedData->headerInfo.generationTime, time(NULL));
            STOP_IT_IF_ERROR(0 != ret, Time64_t, "asn_ulong2INTEGER failed\n");
            
            // ABSENT: expiryTime, generationLocation, p2pcdLearningRequest, missingCrlIdentifier
            //         encryptionKey
            // DO NOTHING: inlineP2pcdRequest, requestedCertificate, pduFunctionalType          
            
            pstSignedData->tbsData = pstToBeSignedData;
            
            pstSignedData->signer
                            .present = SignerIdentifier_PR_self;
            pstSignedData->signer
                            .choice.self = 0;
                            
            pstSignedData->signature
                            .present = Signature_PR_sm2Signature;
            FILL_WITH_OCTET_STRING(             
            pstSignedData->signature
                            .choice.sm2Signature.r, ucs, 32, ret);
            STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            FILL_WITH_OCTET_STRING(
            pstSignedData->signature
                            .choice.sm2Signature.s, ucs, 32, ret);
            STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
                
            pstSubContent->choice.signedData = pstSignedData;
            
            pstSignedElectorEndorsement[j]->content = pstSubContent;
            
            ret = asn_set_add(
            &pstRevokedElectors[i]->endorsements.list, pstSignedElectorEndorsement[j]);
            STOP_IT_IF_ERROR(0 != ret, SignedElectorEndorsement_t, "asn_set_add failed\n");
            
            ASN_STRUCT_FREE(asn_DEF_ScopedElectorEndorsement, pstScopedElectorEndorsement);
        }
                
        ret = asn_set_add(
        &pstScopedRaEeCertResponse->content.choice.ee_ra
                                .choice.raEeCertResponse.reply
                                    .choice.ack
                                        .crl.revokedElectors
                                            .list, pstRevokedElectors[i]);
        STOP_IT_IF_ERROR(0 != ret, CompositeCrl__revokedElectors, "asn_set_add failed\n");
    }
    
    char oerbuf[OERBUFSIZE] = { 0 };
    size_t oerlen = 0;
    asn_enc_rval_t ec = oer_encode_to_buffer(&asn_DEF_ScopedRaEeCertResponse,
                                             NULL,
                                             pstScopedRaEeCertResponse,
                                             oerbuf,
                                             OERBUFSIZE);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode_to_buffer,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    oerlen = ec.encoded;
        
    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.unsecuredData,
            oerbuf,
            oerlen,
            ret);
    STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");
    
    pstSecuredRACertResponse->content = pstIeee1609Dot2Content;
    
    /** 测试 */
    FILE *fp = fopen("SecuredRACertResponse.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_SecuredRACertResponse,
                                     pstSecuredRACertResponse,
                                     write_callback,
                                     (void*)fp);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
                     
    if (fp) fclose(fp);
    fp = fopen("ScopedRaEeCertResponse.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_ScopedRaEeCertResponse,
                    pstScopedRaEeCertResponse,
                    write_callback,
                    (void*)fp);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
        
    // xml print SecuredRACertResponse_t
    xer_fprint(stdout, &asn_DEF_SecuredRACertResponse, pstSecuredRACertResponse);
    // xml print ScopedRaEeCertResponse_t
    xer_fprint(stdout, &asn_DEF_ScopedRaEeCertResponse, pstScopedRaEeCertResponse);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode ra response success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SecuredRACertResponse, pstSecuredRACertResponse);
    ASN_STRUCT_FREE(asn_DEF_ScopedRaEeCertResponse, pstScopedRaEeCertResponse);
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free ra response success ====\n");
    
    return ret;
}

int decode_SecuredRACertResponse(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SecuredRACertResponse_t* pstSecuredRACertResponse = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SecuredRACertResponse, 
                      (void**)&pstSecuredRACertResponse,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SecuredRACertResponse, pstSecuredRACertResponse);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SecuredRACertResponse_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SecuredRACertResponse, pstSecuredRACertResponse);
    if (0 == ret) fprintf(stdout, "==== free SecuredRACertResponse_t success ====\n");
    
    return ret;
}

int decode_ScopedRaEeCertResponse(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    ScopedRaEeCertResponse_t* pstScopedRaEeCertResponse = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_ScopedRaEeCertResponse, 
                      (void**)&pstScopedRaEeCertResponse,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_ScopedRaEeCertResponse, pstScopedRaEeCertResponse);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode ScopedRaEeCertResponse_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_ScopedRaEeCertResponse, pstScopedRaEeCertResponse);
    
    if (0 == ret) fprintf(stdout, "==== free ScopedRaEeCertResponse_t success ====\n");
    
    return ret;
}

int decode_ScopedElectorEndorsement(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    ScopedElectorEndorsement_t* pstScopedElectorEndorsement = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_ScopedElectorEndorsement, 
                      (void**)&pstScopedElectorEndorsement,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_ScopedElectorEndorsement, pstScopedElectorEndorsement);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode ScopedElectorEndorsement_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_ScopedElectorEndorsement, pstScopedElectorEndorsement);
    if (0 == ret) fprintf(stdout, "==== free ScopedElectorEndorsement_t success ====\n");
    
    return ret;
}

int decode_CrlContents(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    CrlContents_t* pstCrlContents = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_CrlContents, 
                      (void**)&pstCrlContents,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_CrlContents, pstCrlContents);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode CrlContents_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_CrlContents, pstCrlContents);
    
    if (0 == ret) fprintf(stdout, "==== free CrlContents_t success ====\n");
    
    return ret;
}

int encode_SecuredPseudonymCertProvisioningRequest()
{
    int ret = -1;
    
    SecuredPseudonymCertProvisioningRequest_t* pstSecuredPseudonymCertProvisioningRequest = NULL;
    
    pstSecuredPseudonymCertProvisioningRequest = 
                                    calloc(1, sizeof(SecuredPseudonymCertProvisioningRequest_t));
    STOP_IT_IF_ERROR(NULL == pstSecuredPseudonymCertProvisioningRequest, 
                     SecuredPseudonymCertProvisioningRequest_t, 
                     "calloc failed\n");
    // Field: protocolVersion
    pstSecuredPseudonymCertProvisioningRequest->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_encryptedData;
    
    struct RecipientInfo* parrRecipientInfo[XSIZE] = { NULL };
    int i;
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrRecipientInfo[i]) {
            parrRecipientInfo[i] = calloc(1, sizeof(struct RecipientInfo));
            STOP_IT_IF_ERROR(NULL == parrRecipientInfo[i], 
                             RecipientInfo_t,
                             "calloc failed\n");
        }
        parrRecipientInfo[i]->present = RecipientInfo_PR_symmRecipInfo;
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.recipientId, ucs, 8, ret);
        STOP_IT_IF_ERROR(0 != ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
        
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .present = SymmetricCiphertext_PR_sm4Ccm;
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .choice.sm4Ccm.nonce, ucs, 12, ret);
        STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .choice.sm4Ccm.ccmCiphertext, ucs, 32, ret);
        STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");

        ret = asn_set_add(&pstIeee1609Dot2Content->choice.encryptedData.recipients.list,
                          parrRecipientInfo[i]);
        STOP_IT_IF_ERROR(0 != ret, RecipientInfo_t, "asn_set_add failed\n");
    }
    
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .present = SymmetricCiphertext_PR_sm4Ccm;
    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .choice.sm4Ccm.nonce, ucs, 12, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");

    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .choice.sm4Ccm.ccmCiphertext, ucs, 64, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    pstSecuredPseudonymCertProvisioningRequest->content = pstIeee1609Dot2Content;
    
    /** 测试 */
    FILE* fp = fopen("SecuredPseudonymCertProvisioningRequest.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    asn_enc_rval_t ec = oer_encode(&asn_DEF_SecuredPseudonymCertProvisioningRequest,
                    pstSecuredPseudonymCertProvisioningRequest,
                    write_callback,
                    (void*)fp);
    // xml print SecuredPseudonymCertProvisioningRequest_t
    xer_fprint(stdout, &asn_DEF_SecuredPseudonymCertProvisioningRequest,
                        pstSecuredPseudonymCertProvisioningRequest);

    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode pc request success ===\n");
    ASN_STRUCT_FREE(asn_DEF_SecuredPseudonymCertProvisioningRequest, 
                    pstSecuredPseudonymCertProvisioningRequest);
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free pc request success ====\n");
    
    
    return ret;
}

int decode_SecuredPseudonymCertProvisioningRequest(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SecuredPseudonymCertProvisioningRequest_t* pstSecuredPseudonymCertProvisioningRequest = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SecuredPseudonymCertProvisioningRequest, 
                      (void**)&pstSecuredPseudonymCertProvisioningRequest,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SecuredPseudonymCertProvisioningRequest,
                        pstSecuredPseudonymCertProvisioningRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SecuredPseudonymCertProvisioningRequest_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SecuredPseudonymCertProvisioningRequest, 
                    pstSecuredPseudonymCertProvisioningRequest);
    if (0 == ret) fprintf(stdout, "==== free SecuredPseudonymCertProvisioningRequest_t success ====\n");
    
    return ret;
}

int encode_SignedPseudonymCertProvisioningRequest()
{
    int ret = -1;
    
    SignedPseudonymCertProvisioningRequest_t* pstSignedPseudonymCertProvisioningRequest = NULL;
    
    pstSignedPseudonymCertProvisioningRequest = calloc(1, sizeof(SignedPseudonymCertProvisioningRequest_t));
    STOP_IT_IF_ERROR(NULL == pstSignedPseudonymCertProvisioningRequest, 
                     SignedPseudonymCertProvisioningRequest_t, 
                     "calloc failed\n");
    // Field: protocolVersion
    pstSignedPseudonymCertProvisioningRequest->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_signedCertificateRequest;
    /** 不透明指针 - SignedCertificateRequest */
    struct SignedCertificateRequest* pstSignedCertificateRequest = NULL;
    pstSignedCertificateRequest = calloc(1, sizeof(struct SignedCertificateRequest));
    STOP_IT_IF_ERROR(NULL == pstSignedCertificateRequest, 
                     SignedCertificateRequest_t, 
                     "calloc failed\n");
    
    pstSignedCertificateRequest->hashId = HashAlgorithm_sm3;
    pstSignedCertificateRequest->tbsRequest
                            .version = ScmsPDUVersion;
    pstSignedCertificateRequest->tbsRequest
                            .content.present = ScmsPDU__content_PR_ee_ra;
    pstSignedCertificateRequest->tbsRequest
                            .content.choice.ee_ra
                                .present = EndEntityRaInterfacePDU_PR_eeRaPseudonymCertProvisioningRequest;
    pstSignedCertificateRequest->tbsRequest
                            .content.choice.ee_ra
                                .choice.eeRaPseudonymCertProvisioningRequest
                                    .version = RaPseCertReqVersion;
    pstSignedCertificateRequest->tbsRequest
                            .content.choice.ee_ra
                                .choice.eeRaPseudonymCertProvisioningRequest
                                    .verify_key_info.seed_key
                                        .present = EccP256CurvePoint_PR_x_only;
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->tbsRequest
                            .content.choice.ee_ra
                                .choice.eeRaPseudonymCertProvisioningRequest
                                    .verify_key_info.seed_key
                                        .choice.x_only, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->tbsRequest
                            .content.choice.ee_ra
                                .choice.eeRaPseudonymCertProvisioningRequest
                                    .verify_key_info.expansion, ucs, 16, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    pstSignedCertificateRequest->tbsRequest
                            .content.choice.ee_ra
                                .choice.eeRaPseudonymCertProvisioningRequest
                                    .resp_enc_key_info.seed_key
                                        .present = EccP256CurvePoint_PR_x_only;
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->tbsRequest
                            .content.choice.ee_ra
                                .choice.eeRaPseudonymCertProvisioningRequest
                                    .resp_enc_key_info.seed_key
                                        .choice.x_only, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->tbsRequest
                            .content.choice.ee_ra
                                .choice.eeRaPseudonymCertProvisioningRequest
                                    .resp_enc_key_info.expansion, ucs, 16, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    pstSignedCertificateRequest->tbsRequest
                            .content.choice.ee_ra
                                .choice.eeRaPseudonymCertProvisioningRequest
                                    .common.current_time = time(NULL);
    pstSignedCertificateRequest->tbsRequest
                            .content.choice.ee_ra
                                .choice.eeRaPseudonymCertProvisioningRequest
                                    .common.requested_start_time = time(NULL) - 0x1234; 

    pstSignedCertificateRequest->signer
                            .present = SignerIdentifier_PR_certificate;
    
    Certificate_t* parrCertificate[XSIZE] = { NULL };
    int i;
    for (i = 0; i < ONESIZE; i++) {
        if (NULL == parrCertificate[i]) {
            parrCertificate[i] = calloc(1, sizeof(Certificate_t));
            STOP_IT_IF_ERROR(NULL == parrCertificate[i], 
                             Certificate_t,
                             "calloc failed\n");
        }
        
        parrCertificate[i]->version = CertificateVersion;
        parrCertificate[i]->type = CertificateType_implicit;
        parrCertificate[i]->issuer.present = IssuerIdentifier_PR_self;
        parrCertificate[i]->issuer.choice.self = HashAlgorithm_sm3;
        parrCertificate[i]->toBeSigned.id.present = CertificateId_PR_none;
        parrCertificate[i]->toBeSigned.id.choice.none = 0;
        FILL_WITH_OCTET_STRING(
        parrCertificate[i]->toBeSigned.cracaId, ucs, 3, ret);
        STOP_IT_IF_ERROR(0 != ret, HashedId3_t, "OCTET_STRING_fromBuf failed\n");
        parrCertificate[i]->toBeSigned.crlSeries = 65513;
        parrCertificate[i]->toBeSigned.validityPeriod.start = time(NULL);
        parrCertificate[i]->toBeSigned.validityPeriod.duration.present = Duration_PR_years;
        parrCertificate[i]->toBeSigned.validityPeriod.duration.choice.years = 16;
        
        struct SequenceOfPsidSsp* pstAppPermissions = NULL;
        pstAppPermissions = calloc(1, sizeof(struct SequenceOfPsidSsp));
        STOP_IT_IF_ERROR(NULL == pstAppPermissions,
                         SequenceOfPsidSsp_t,
                         "calloc failed\n");
        struct PsidSsp* parrPsidSsp[XSIZE] = { NULL };
        int j;
        for (j = 0; j < YSIZE; j++) {
            if (NULL == parrPsidSsp[j]) {
                parrPsidSsp[j] = calloc(1, sizeof(struct PsidSsp));
                STOP_IT_IF_ERROR(NULL == parrPsidSsp[j], PsidSsp_t, "calloc failed\n");
            }
            parrPsidSsp[j]->psid = 100;
            parrPsidSsp[j]->ssp = calloc(1, sizeof(struct ServiceSpecificPermissions));
            STOP_IT_IF_ERROR(NULL == parrPsidSsp[j]->ssp,
                             ServiceSpecificPermissions_t,
                             "calloc failed\n");
            parrPsidSsp[j]->ssp->present = ServiceSpecificPermissions_PR_opaque;
            FILL_WITH_OCTET_STRING(parrPsidSsp[j]->ssp->choice.opaque, ucs, -1, ret);
            STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            ret = asn_set_add(&pstAppPermissions->list, parrPsidSsp[j]);
            STOP_IT_IF_ERROR(0 != ret, ServiceSpecificPermissions_t, "asn_set_add failed\n");
        }
        parrCertificate[i]->toBeSigned.appPermissions = pstAppPermissions;
        
        struct SequenceOfPsidGroupPermissions* pstCertIssuePermissions = NULL;
        pstCertIssuePermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
        STOP_IT_IF_ERROR(NULL == pstCertIssuePermissions, 
                         SequenceOfPsidGroupPermissions_t, 
                         "calloc failed\n");
        struct PsidGroupPermissions* parrCertIssuePermissions[XSIZE] = { NULL };
        for (j = 0; j < YSIZE; j++) {
            if (NULL == parrCertIssuePermissions[j]) {
                parrCertIssuePermissions[j] = calloc(1, sizeof(struct PsidGroupPermissions));
                STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[j], 
                                 PsidGroupPermissions_t,
                                 "calloc failed\n");
            }
            parrCertIssuePermissions[j]->subjectPermissions.present = SubjectPermissions_PR_all;
            parrCertIssuePermissions[j]->subjectPermissions.choice.all = 0;
            
            if (NULL == parrCertIssuePermissions[j]->minChainLength) {
                parrCertIssuePermissions[j]->minChainLength = calloc(1, sizeof(long));
                STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[j]->minChainLength, 
                                 long_t,
                                 "calloc failed\n");
            }
            *parrCertIssuePermissions[j]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
            
            parrCertIssuePermissions[j]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
            
            if (NULL == parrCertIssuePermissions[j]->eeType) {
                parrCertIssuePermissions[j]->eeType = calloc(1, sizeof(EndEntityType_t));
                STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[j]->eeType, 
                                 EndEntityType_t,
                                 "calloc failed\n");
            }
            if (NULL == parrCertIssuePermissions[j]->eeType->buf) {
                parrCertIssuePermissions[j]->eeType->buf = calloc(1, 1);
                STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[j]->eeType->buf, 
                                 uint8_t,
                                 "calloc failed\n");
            }
            parrCertIssuePermissions[j]->eeType->size = 1;
            parrCertIssuePermissions[j]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
            parrCertIssuePermissions[j]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
            parrCertIssuePermissions[j]->eeType->bits_unused = 6;
            
            ret = asn_set_add(&pstCertIssuePermissions->list, parrCertIssuePermissions[j]);
            STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
        }
        parrCertificate[i]->toBeSigned.certIssuePermissions = pstCertIssuePermissions;
        
        struct SequenceOfPsidGroupPermissions* pstCertRequestPermissions = NULL;
        pstCertRequestPermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
        STOP_IT_IF_ERROR(NULL == pstCertRequestPermissions, 
                         SequenceOfPsidGroupPermissions_t, 
                         "calloc failed\n");
        struct PsidGroupPermissions* parrCertRequestPermissions[XSIZE] = { NULL };
        for (j = 0; j < YSIZE; j++) {
            if (NULL == parrCertRequestPermissions[j]) {
                parrCertRequestPermissions[j] = calloc(1, sizeof(struct PsidGroupPermissions));
                STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[j], 
                                 PsidGroupPermissions_t,
                                 "calloc failed\n");
            }
            parrCertRequestPermissions[j]->subjectPermissions.present = SubjectPermissions_PR_all;
            parrCertRequestPermissions[j]->subjectPermissions.choice.all = 0;
            
            if (NULL == parrCertRequestPermissions[j]->minChainLength) {
                parrCertRequestPermissions[j]->minChainLength = calloc(1, sizeof(long));
                STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[j]->minChainLength, 
                                 long_t,
                                 "calloc failed\n");
            }
            *parrCertRequestPermissions[j]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
            
            parrCertRequestPermissions[j]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
            
            if (NULL == parrCertRequestPermissions[j]->eeType) {
                parrCertRequestPermissions[j]->eeType = calloc(1, sizeof(EndEntityType_t));
                STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[j]->eeType, 
                                 EndEntityType_t,
                                 "calloc failed\n");
            }
            if (NULL == parrCertRequestPermissions[j]->eeType->buf) {
                parrCertRequestPermissions[j]->eeType->buf = calloc(1, 1);
                STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[j]->eeType->buf, 
                                 uint8_t,
                                 "calloc failed\n");
            }
            parrCertRequestPermissions[j]->eeType->size = 1;
            parrCertRequestPermissions[j]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
            parrCertRequestPermissions[j]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
            parrCertRequestPermissions[j]->eeType->bits_unused = 6;
            
            ret = asn_set_add(&pstCertRequestPermissions->list, parrCertRequestPermissions[j]);
            STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
        }
        parrCertificate[i]->toBeSigned.certRequestPermissions = pstCertRequestPermissions;
        
        parrCertificate[i]->toBeSigned.verifyKeyIndicator
                                .present = VerificationKeyIndicator_PR_reconstructionValue;
        parrCertificate[i]->toBeSigned.verifyKeyIndicator
                                .choice.reconstructionValue
                                    .present = EccP256CurvePoint_PR_x_only;
        FILL_WITH_OCTET_STRING(
        parrCertificate[i]->toBeSigned.verifyKeyIndicator
                                .choice.reconstructionValue
                                    .choice.x_only, ucs, 32, ret);
        STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        
        ret = asn_set_add(
        &pstSignedCertificateRequest->signer
                            .choice.certificate.list, parrCertificate[i]);
        STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
    }

    pstSignedCertificateRequest->signature
                            .present = Signature_PR_sm2Signature;
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->signature
                    .choice.sm2Signature.r, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->signature
                    .choice.sm2Signature.s, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    char oerbuf[OERBUFSIZE] = { 0 };
    size_t oerlen = 0;
    asn_enc_rval_t ec = oer_encode_to_buffer(&asn_DEF_SignedCertificateRequest,
                                             NULL,
                                             pstSignedCertificateRequest,
                                             oerbuf,
                                             OERBUFSIZE);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode_to_buffer,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    oerlen = ec.encoded;

    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.signedCertificateRequest,
                           oerbuf, 
                           oerlen,
                           ret);
    STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");
    
    pstSignedPseudonymCertProvisioningRequest->content = pstIeee1609Dot2Content;
    
    /** 测试 */
    FILE* fp = fopen("SignedPseudonymCertProvisioningRequest.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_SignedPseudonymCertProvisioningRequest,
                                     pstSignedPseudonymCertProvisioningRequest,
                                     write_callback,
                                     (void*)fp);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    if (fp) fclose(fp);
    fp = fopen("SignedCertificateRequest.rapseureq.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_SignedCertificateRequest,
                    pstSignedCertificateRequest,
                    write_callback,
                    (void*)fp);
    
    // xml print SignedPseudonymCertProvisioningRequest_t
    xer_fprint(stdout, &asn_DEF_SignedPseudonymCertProvisioningRequest, 
               pstSignedPseudonymCertProvisioningRequest);
    // xml print SignedCertificateRequest_t
    xer_fprint(stdout, &asn_DEF_SignedCertificateRequest, pstSignedCertificateRequest);
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode ra pseu request success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedPseudonymCertProvisioningRequest,
                    pstSignedPseudonymCertProvisioningRequest);
    ASN_STRUCT_FREE(asn_DEF_SignedCertificateRequest, pstSignedCertificateRequest);
                    
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free ra pseu request success ====\n");

    return ret;
}

int decode_SignedPseudonymCertProvisioningRequest(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SignedPseudonymCertProvisioningRequest_t* pstSignedPseudonymCertProvisioningRequest = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SignedPseudonymCertProvisioningRequest, 
                      (void**)&pstSignedPseudonymCertProvisioningRequest,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SignedPseudonymCertProvisioningRequest, 
                        pstSignedPseudonymCertProvisioningRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SignedPseudonymCertProvisioningRequest success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedPseudonymCertProvisioningRequest, 
                    pstSignedPseudonymCertProvisioningRequest);
    if (0 == ret) fprintf(stdout, "==== free SignedPseudonymCertProvisioningRequest success ====\n");
    
    return ret;
}

int encode_SecuredPseudonymCertProvisioningAck()
{
    int ret = -1;
    
    SecuredPseudonymCertProvisioningAck_t* pstSecuredPseudonymCertProvisioningAck = NULL;
    
    pstSecuredPseudonymCertProvisioningAck = calloc(1, sizeof(SecuredPseudonymCertProvisioningAck_t));
    STOP_IT_IF_ERROR(NULL == pstSecuredPseudonymCertProvisioningAck, 
                     SecuredPseudonymCertProvisioningAck_t, 
                     "calloc failed\n");
    // Field: protocolVersion
    pstSecuredPseudonymCertProvisioningAck->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_encryptedData;

    struct RecipientInfo* parrRecipientInfo[XSIZE] = { NULL };
    int i;
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrRecipientInfo[i]) {
            parrRecipientInfo[i] = calloc(1, sizeof(struct RecipientInfo));
            STOP_IT_IF_ERROR(NULL == parrRecipientInfo[i], 
                             RecipientInfo_t,
                             "calloc failed\n");
        }
        parrRecipientInfo[i]->present = RecipientInfo_PR_symmRecipInfo;
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.recipientId, ucs, 8, ret);
        STOP_IT_IF_ERROR(0 != ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
        
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .present = SymmetricCiphertext_PR_sm4Ccm;
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .choice.sm4Ccm.nonce, ucs, 12, ret);
        STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .choice.sm4Ccm.ccmCiphertext, ucs, 32, ret);
        STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");

        ret = asn_set_add(&pstIeee1609Dot2Content->choice.encryptedData.recipients.list,
                          parrRecipientInfo[i]);
        STOP_IT_IF_ERROR(0 != ret, RecipientInfo_t, "asn_set_add failed\n");
    }
    
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .present = SymmetricCiphertext_PR_sm4Ccm;
    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .choice.sm4Ccm.nonce, ucs, 12, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");

    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .choice.sm4Ccm.ccmCiphertext, ucs, 64, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    pstSecuredPseudonymCertProvisioningAck->content = pstIeee1609Dot2Content;

    /** 测试 */
    FILE* fp = fopen("SecuredPseudonymCertProvisioningAck.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    asn_enc_rval_t ec = oer_encode(&asn_DEF_SecuredPseudonymCertProvisioningAck,
                    pstSecuredPseudonymCertProvisioningAck,
                    write_callback,
                    (void*)fp);
    // xml print SecuredPseudonymCertProvisioningAck_t
    xer_fprint(stdout, &asn_DEF_SecuredPseudonymCertProvisioningAck,
                        pstSecuredPseudonymCertProvisioningAck);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode pc ack success ===\n");
    ASN_STRUCT_FREE(asn_DEF_SecuredPseudonymCertProvisioningAck, 
                    pstSecuredPseudonymCertProvisioningAck);
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free pc ack success ====\n");
    
    return ret;
}

int decode_SecuredPseudonymCertProvisioningAck(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SecuredPseudonymCertProvisioningAck_t* pstSecuredPseudonymCertProvisioningAck = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SecuredPseudonymCertProvisioningAck, 
                      (void**)&pstSecuredPseudonymCertProvisioningAck,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SecuredPseudonymCertProvisioningAck, 
                       pstSecuredPseudonymCertProvisioningAck);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SecuredPseudonymCertProvisioningAck_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SecuredPseudonymCertProvisioningAck, 
                    pstSecuredPseudonymCertProvisioningAck);
    
    if (0 == ret) fprintf(stdout, "==== free SecuredPseudonymCertProvisioningAck_t success ====\n");
    
    return ret;
    
}

int encode_SignedPseudonymCertProvisioningAck()
{
    int ret = -1;
    
    SignedPseudonymCertProvisioningAck_t* pstSignedPseudonymCertProvisioningAck = NULL;
    
    pstSignedPseudonymCertProvisioningAck = calloc(1, sizeof(SignedPseudonymCertProvisioningAck_t));
    STOP_IT_IF_ERROR(NULL == pstSignedPseudonymCertProvisioningAck, 
                     SignedPseudonymCertProvisioningAck_t, 
                     "calloc failed\n");
    // Field: protocolVersion
    pstSignedPseudonymCertProvisioningAck->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_signedData;

    struct SignedData* pstSignedData = NULL;
    pstSignedData = calloc(1, sizeof(struct SignedData));
    STOP_IT_IF_ERROR(NULL == pstSignedData,
                     SignedData_t, 
                     "calloc failed\n");
    
    pstSignedData->hashId = HashAlgorithm_sm3;
    
    struct ToBeSignedData* pstToBeSignedData = NULL;
    pstToBeSignedData = calloc(1, sizeof(struct ToBeSignedData));
    STOP_IT_IF_ERROR(NULL == pstToBeSignedData, 
                     ToBeSignedData_t, 
                     "calloc failed\n");
                     
    struct SignedDataPayload* pstSignedDataPayload = NULL;
    pstSignedDataPayload = calloc(1, sizeof(struct SignedDataPayload));
    STOP_IT_IF_ERROR(NULL == pstSignedDataPayload, 
                     SignedDataPayload_t, 
                     "calloc failed\n");
    
    struct Ieee1609Dot2Data* pstIeee1609Dot2Data = NULL;
    pstIeee1609Dot2Data = calloc(1, sizeof(struct Ieee1609Dot2Data));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Data, 
                     Ieee1609Dot2Data_t, 
                     "calloc failed\n");
    
    pstIeee1609Dot2Data->protocolVersion = ProtocolVersion;
    
    struct Ieee1609Dot2Content* pstIeee1609Dot2ContentUnsecuredData = NULL;
    pstIeee1609Dot2ContentUnsecuredData = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2ContentUnsecuredData, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2ContentUnsecuredData->present = Ieee1609Dot2Content_PR_unsecuredData;
    
    /** 不透明指针 - ScopedPseudonymCertProvisioningAck */
    ScopedPseudonymCertProvisioningAck_t *pstScopedPseudonymCertProvisioningAck = NULL;
    pstScopedPseudonymCertProvisioningAck = calloc(1, sizeof(ScopedPseudonymCertProvisioningAck_t));
    STOP_IT_IF_ERROR(NULL == pstScopedPseudonymCertProvisioningAck, 
                     ScopedPseudonymCertProvisioningAck_t, 
                     "calloc failed\n");
    
    pstScopedPseudonymCertProvisioningAck->version = ScmsPDUVersion;
    pstScopedPseudonymCertProvisioningAck->content
                            .present = ScmsPDU__content_PR_ee_ra;
    pstScopedPseudonymCertProvisioningAck->content
                            .choice.ee_ra
                                .present = EndEntityRaInterfacePDU_PR_raEePseudonymCertProvisioningAck;
    pstScopedPseudonymCertProvisioningAck->content
                            .choice.ee_ra
                                .choice.raEePseudonymCertProvisioningAck
                                    .version = RaPseCertAckVersion;
    FILL_WITH_OCTET_STRING(
    pstScopedPseudonymCertProvisioningAck->content
                            .choice.ee_ra
                                .choice.raEePseudonymCertProvisioningAck
                                    .requestHash, ucs, 8, ret);
    STOP_IT_IF_ERROR(0 != ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
    
    pstScopedPseudonymCertProvisioningAck->content
                            .choice.ee_ra
                                .choice.raEePseudonymCertProvisioningAck
                                    .reply.present = RaEePseudonymCertProvisioningAck__reply_PR_ack;
    pstScopedPseudonymCertProvisioningAck->content
                            .choice.ee_ra
                                .choice.raEePseudonymCertProvisioningAck
                                    .reply.choice.ack
                                        .certDLTime = time(NULL);
    FILL_WITH_OCTET_STRING(
    pstScopedPseudonymCertProvisioningAck->content
                            .choice.ee_ra
                                .choice.raEePseudonymCertProvisioningAck
                                    .reply.choice.ack
                                        .certDLURL, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
    
    
    char oerbuf[OERBUFSIZE] = { 0 };
    size_t oerlen = 0;
    asn_enc_rval_t ec = oer_encode_to_buffer(&asn_DEF_ScopedPseudonymCertProvisioningAck,
                                             NULL,
                                             pstScopedPseudonymCertProvisioningAck,
                                             oerbuf,
                                             OERBUFSIZE);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode_to_buffer,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    oerlen = ec.encoded;
    
    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2ContentUnsecuredData->choice.unsecuredData,
            oerbuf,
            oerlen,
            ret);
    STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");
    
    pstIeee1609Dot2Data->content = pstIeee1609Dot2ContentUnsecuredData;
    
    pstSignedDataPayload->data = pstIeee1609Dot2Data;
    
    // pstSignedDataPayload->extDataHash = ... // do nothing
    
    pstToBeSignedData->payload = pstSignedDataPayload;
    
    pstToBeSignedData->headerInfo.psid = PsidValue;     // data

    pstSignedData->tbsData = pstToBeSignedData;
    
    pstSignedData->signer.present = SignerIdentifier_PR_self;
    pstSignedData->signer.choice.self = 0;
    
    pstSignedData->signature
                    .present = Signature_PR_sm2Signature;
    
    FILL_WITH_OCTET_STRING(
    pstSignedData->signature
                    .choice.sm2Signature.r, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    FILL_WITH_OCTET_STRING(
    pstSignedData->signature
                    .choice.sm2Signature.s, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    pstIeee1609Dot2Content->choice.signedData = pstSignedData;
    
    pstSignedPseudonymCertProvisioningAck->content = pstIeee1609Dot2Content;
    
    /** 测试 */
    FILE *fp = fopen("SignedPseudonymCertProvisioningAck.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_SignedPseudonymCertProvisioningAck,
                     pstSignedPseudonymCertProvisioningAck,
                     write_callback,
                     (void*)fp);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
                     
    if (fp) fclose(fp);
    fp = fopen("ScopedPseudonymCertProvisioningAck.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_ScopedPseudonymCertProvisioningAck,
                    pstScopedPseudonymCertProvisioningAck,
                    write_callback,
                    (void*)fp);
    // xml print SignedPseudonymCertProvisioningAck_t
    xer_fprint(stdout, &asn_DEF_SignedPseudonymCertProvisioningAck,
                        pstSignedPseudonymCertProvisioningAck);
    // xml print ScopedPseudonymCertProvisioningAck_t
    xer_fprint(stdout, &asn_DEF_ScopedPseudonymCertProvisioningAck, 
                        pstScopedPseudonymCertProvisioningAck);
    printf("\n");

    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode pc ack success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedPseudonymCertProvisioningAck, pstSignedPseudonymCertProvisioningAck);
    ASN_STRUCT_FREE(asn_DEF_ScopedPseudonymCertProvisioningAck, pstScopedPseudonymCertProvisioningAck);
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free pc ack success ====\n");
    
    return ret;
}

int decode_SignedPseudonymCertProvisioningAck(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SignedPseudonymCertProvisioningAck_t* pstSignedPseudonymCertProvisioningAck = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SignedPseudonymCertProvisioningAck, 
                      (void**)&pstSignedPseudonymCertProvisioningAck,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SignedPseudonymCertProvisioningAck, pstSignedPseudonymCertProvisioningAck);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SignedPseudonymCertProvisioningAck_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedPseudonymCertProvisioningAck, pstSignedPseudonymCertProvisioningAck);
    if (0 == ret) fprintf(stdout, "==== free SignedPseudonymCertProvisioningAck_t success ====\n");
    
    return ret;
}

int decode_ScopedPseudonymCertProvisioningAck(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    ScopedPseudonymCertProvisioningAck_t* pstScopedPseudonymCertProvisioningAck = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_ScopedPseudonymCertProvisioningAck, 
                      (void**)&pstScopedPseudonymCertProvisioningAck,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_ScopedPseudonymCertProvisioningAck, pstScopedPseudonymCertProvisioningAck);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode ScopedPseudonymCertProvisioningAck_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_ScopedPseudonymCertProvisioningAck, pstScopedPseudonymCertProvisioningAck);
    if (0 == ret) fprintf(stdout, "==== free ScopedPseudonymCertProvisioningAck_t success ====\n");
    
    return ret; 
}

int encode_SecuredAuthenticatedDownloadRequest()
{
    int ret = -1;
    
    SecuredAuthenticatedDownloadRequest_t* pstSecuredAuthenticatedDownloadRequest = NULL;
    
    pstSecuredAuthenticatedDownloadRequest = 
                                    calloc(1, sizeof(SecuredAuthenticatedDownloadRequest_t));
    STOP_IT_IF_ERROR(NULL == pstSecuredAuthenticatedDownloadRequest, 
                     SecuredAuthenticatedDownloadRequest_t, 
                     "calloc failed\n");
    // Field: protocolVersion
    pstSecuredAuthenticatedDownloadRequest->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_encryptedData;
    
    struct RecipientInfo* parrRecipientInfo[XSIZE] = { NULL };
    int i;
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrRecipientInfo[i]) {
            parrRecipientInfo[i] = calloc(1, sizeof(struct RecipientInfo));
            STOP_IT_IF_ERROR(NULL == parrRecipientInfo[i], 
                             RecipientInfo_t,
                             "calloc failed\n");
        }
        parrRecipientInfo[i]->present = RecipientInfo_PR_symmRecipInfo;
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.recipientId, ucs, 8, ret);
        STOP_IT_IF_ERROR(0 != ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
        
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .present = SymmetricCiphertext_PR_sm4Ccm;
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .choice.sm4Ccm.nonce, ucs, 12, ret);
        STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .choice.sm4Ccm.ccmCiphertext, ucs, 32, ret);
        STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");

        ret = asn_set_add(&pstIeee1609Dot2Content->choice.encryptedData.recipients.list,
                          parrRecipientInfo[i]);
        STOP_IT_IF_ERROR(0 != ret, RecipientInfo_t, "asn_set_add failed\n");
    }
    
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .present = SymmetricCiphertext_PR_sm4Ccm;
    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .choice.sm4Ccm.nonce, ucs, 12, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");

    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .choice.sm4Ccm.ccmCiphertext, ucs, 64, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    pstSecuredAuthenticatedDownloadRequest->content = pstIeee1609Dot2Content;
    
    /** 测试 */
    FILE* fp = fopen("SecuredAuthenticatedDownloadRequest.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    asn_enc_rval_t ec = oer_encode(&asn_DEF_SecuredAuthenticatedDownloadRequest,
                    pstSecuredAuthenticatedDownloadRequest,
                    write_callback,
                    (void*)fp);
    // xml print SecuredAuthenticatedDownloadRequest_t
    xer_fprint(stdout, &asn_DEF_SecuredAuthenticatedDownloadRequest,
                        pstSecuredAuthenticatedDownloadRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode pc download success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SecuredAuthenticatedDownloadRequest, 
                    pstSecuredAuthenticatedDownloadRequest);
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free pc download success ====\n");
    
    return ret;
}

int decode_SecuredAuthenticatedDownloadRequest(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SecuredAuthenticatedDownloadRequest_t* pstSecuredAuthenticatedDownloadRequest = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SecuredAuthenticatedDownloadRequest, 
                      (void**)&pstSecuredAuthenticatedDownloadRequest,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SecuredAuthenticatedDownloadRequest,
                        pstSecuredAuthenticatedDownloadRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SecuredAuthenticatedDownloadRequest_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SecuredAuthenticatedDownloadRequest, 
                    pstSecuredAuthenticatedDownloadRequest);

    if (0 == ret) fprintf(stdout, "==== free SecuredAuthenticatedDownloadRequest_t success ====\n");
    
    return ret;
}

int encode_SignedAuthenticatedDownloadRequest()
{
    int ret = -1;
    
    SignedAuthenticatedDownloadRequest_t* pstSignedAuthenticatedDownloadRequest = NULL;
    
    pstSignedAuthenticatedDownloadRequest = 
                                    calloc(1, sizeof(SignedAuthenticatedDownloadRequest_t));
    STOP_IT_IF_ERROR(NULL == pstSignedAuthenticatedDownloadRequest, 
                     SignedAuthenticatedDownloadRequest_t, 
                     "calloc failed\n");
    // Field: protocolVersion
    pstSignedAuthenticatedDownloadRequest->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_signedCertificateRequest;
    
    /** 不透明指针 */
    struct SignedCertificateRequest* pstSignedCertificateRequest = NULL;
    pstSignedCertificateRequest = calloc(1, sizeof(struct SignedCertificateRequest));
    STOP_IT_IF_ERROR(NULL == pstSignedCertificateRequest, 
                     SignedCertificateRequest_t, 
                     "calloc failed\n");
    pstSignedCertificateRequest->hashId = HashAlgorithm_sm3;
    pstSignedCertificateRequest->tbsRequest
                            .version = ScmsPDUVersion;
    pstSignedCertificateRequest->tbsRequest
                            .content.present = ScmsPDU__content_PR_ee_ra;
    pstSignedCertificateRequest->tbsRequest
                            .content.choice.ee_ra
                                .present = EndEntityRaInterfacePDU_PR_eeRaAuthenticatedDownloadRequest;
    pstSignedCertificateRequest->tbsRequest
                            .content.choice.ee_ra
                                .choice.eeRaAuthenticatedDownloadRequest
                                    .timestamp = time(NULL);
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->tbsRequest
                            .content.choice.ee_ra
                                .choice.eeRaAuthenticatedDownloadRequest
                                    .filename, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    pstSignedCertificateRequest->signer
                        .present = SignerIdentifier_PR_certificate;
    pstSignedCertificateRequest->signer
                        .choice.self = 0;
    
    Certificate_t* parrCertificate[XSIZE] = { NULL };
    int i;
    for (i = 0; i < ONESIZE; i++) {
        if (NULL == parrCertificate[i]) {
            parrCertificate[i] = calloc(1, sizeof(Certificate_t));
            STOP_IT_IF_ERROR(NULL == parrCertificate[i], 
                             Certificate_t,
                             "calloc failed\n");
        }
        
        parrCertificate[i]->version = CertificateVersion;
        parrCertificate[i]->type = CertificateType_implicit;
        parrCertificate[i]->issuer.present = IssuerIdentifier_PR_self;
        parrCertificate[i]->issuer.choice.self = HashAlgorithm_sm3;
        parrCertificate[i]->toBeSigned.id.present = CertificateId_PR_none;
        parrCertificate[i]->toBeSigned.id.choice.none = 0;
        FILL_WITH_OCTET_STRING(
        parrCertificate[i]->toBeSigned.cracaId, ucs, 3, ret);
        STOP_IT_IF_ERROR(0 != ret, HashedId3_t, "OCTET_STRING_fromBuf failed\n");
        parrCertificate[i]->toBeSigned.crlSeries = 65513;
        parrCertificate[i]->toBeSigned.validityPeriod.start = time(NULL);
        parrCertificate[i]->toBeSigned.validityPeriod.duration.present = Duration_PR_years;
        parrCertificate[i]->toBeSigned.validityPeriod.duration.choice.years = 16;
        
        struct SequenceOfPsidSsp* pstAppPermissions = NULL;
        pstAppPermissions = calloc(1, sizeof(struct SequenceOfPsidSsp));
        STOP_IT_IF_ERROR(NULL == pstAppPermissions,
                         SequenceOfPsidSsp_t,
                         "calloc failed\n");
        struct PsidSsp* parrPsidSsp[XSIZE] = { NULL };
        int j;
        for (j = 0; j < YSIZE; j++) {
            if (NULL == parrPsidSsp[j]) {
                parrPsidSsp[j] = calloc(1, sizeof(struct PsidSsp));
                STOP_IT_IF_ERROR(NULL == parrPsidSsp[j], PsidSsp_t, "calloc failed\n");
            }
            parrPsidSsp[j]->psid = 100;
            parrPsidSsp[j]->ssp = calloc(1, sizeof(struct ServiceSpecificPermissions));
            STOP_IT_IF_ERROR(NULL == parrPsidSsp[j]->ssp,
                             ServiceSpecificPermissions_t,
                             "calloc failed\n");
            parrPsidSsp[j]->ssp->present = ServiceSpecificPermissions_PR_opaque;
            FILL_WITH_OCTET_STRING(parrPsidSsp[j]->ssp->choice.opaque, ucs, -1, ret);
            STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            ret = asn_set_add(&pstAppPermissions->list, parrPsidSsp[j]);
            STOP_IT_IF_ERROR(0 != ret, ServiceSpecificPermissions_t, "asn_set_add failed\n");
        }
        parrCertificate[i]->toBeSigned.appPermissions = pstAppPermissions;
        
        struct SequenceOfPsidGroupPermissions* pstCertIssuePermissions = NULL;
        pstCertIssuePermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
        STOP_IT_IF_ERROR(NULL == pstCertIssuePermissions, 
                         SequenceOfPsidGroupPermissions_t, 
                         "calloc failed\n");
        struct PsidGroupPermissions* parrCertIssuePermissions[XSIZE] = { NULL };
        for (j = 0; j < YSIZE; j++) {
            if (NULL == parrCertIssuePermissions[j]) {
                parrCertIssuePermissions[j] = calloc(1, sizeof(struct PsidGroupPermissions));
                STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[j], 
                                 PsidGroupPermissions_t,
                                 "calloc failed\n");
            }
            parrCertIssuePermissions[j]->subjectPermissions.present = SubjectPermissions_PR_all;
            parrCertIssuePermissions[j]->subjectPermissions.choice.all = 0;
            
            if (NULL == parrCertIssuePermissions[j]->minChainLength) {
                parrCertIssuePermissions[j]->minChainLength = calloc(1, sizeof(long));
                STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[j]->minChainLength, 
                                 long_t,
                                 "calloc failed\n");
            }
            *parrCertIssuePermissions[j]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
            
            parrCertIssuePermissions[j]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
            
            if (NULL == parrCertIssuePermissions[j]->eeType) {
                parrCertIssuePermissions[j]->eeType = calloc(1, sizeof(EndEntityType_t));
                STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[j]->eeType, 
                                 EndEntityType_t,
                                 "calloc failed\n");
            }
            if (NULL == parrCertIssuePermissions[j]->eeType->buf) {
                parrCertIssuePermissions[j]->eeType->buf = calloc(1, 1);
                STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[j]->eeType->buf, 
                                 uint8_t,
                                 "calloc failed\n");
            }
            parrCertIssuePermissions[j]->eeType->size = 1;
            parrCertIssuePermissions[j]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
            parrCertIssuePermissions[j]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
            parrCertIssuePermissions[j]->eeType->bits_unused = 6;
            
            ret = asn_set_add(&pstCertIssuePermissions->list, parrCertIssuePermissions[j]);
            STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
        }
        parrCertificate[i]->toBeSigned.certIssuePermissions = pstCertIssuePermissions;
        
        struct SequenceOfPsidGroupPermissions* pstCertRequestPermissions = NULL;
        pstCertRequestPermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
        STOP_IT_IF_ERROR(NULL == pstCertRequestPermissions, 
                         SequenceOfPsidGroupPermissions_t, 
                         "calloc failed\n");
        struct PsidGroupPermissions* parrCertRequestPermissions[XSIZE] = { NULL };
        for (j = 0; j < YSIZE; j++) {
            if (NULL == parrCertRequestPermissions[j]) {
                parrCertRequestPermissions[j] = calloc(1, sizeof(struct PsidGroupPermissions));
                STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[j], 
                                 PsidGroupPermissions_t,
                                 "calloc failed\n");
            }
            parrCertRequestPermissions[j]->subjectPermissions.present = SubjectPermissions_PR_all;
            parrCertRequestPermissions[j]->subjectPermissions.choice.all = 0;
            
            if (NULL == parrCertRequestPermissions[j]->minChainLength) {
                parrCertRequestPermissions[j]->minChainLength = calloc(1, sizeof(long));
                STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[j]->minChainLength, 
                                 long_t,
                                 "calloc failed\n");
            }
            *parrCertRequestPermissions[j]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
            
            parrCertRequestPermissions[j]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
            
            if (NULL == parrCertRequestPermissions[j]->eeType) {
                parrCertRequestPermissions[j]->eeType = calloc(1, sizeof(EndEntityType_t));
                STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[j]->eeType, 
                                 EndEntityType_t,
                                 "calloc failed\n");
            }
            if (NULL == parrCertRequestPermissions[j]->eeType->buf) {
                parrCertRequestPermissions[j]->eeType->buf = calloc(1, 1);
                STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[j]->eeType->buf, 
                                 uint8_t,
                                 "calloc failed\n");
            }
            parrCertRequestPermissions[j]->eeType->size = 1;
            parrCertRequestPermissions[j]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
            parrCertRequestPermissions[j]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
            parrCertRequestPermissions[j]->eeType->bits_unused = 6;
            
            ret = asn_set_add(&pstCertRequestPermissions->list, parrCertRequestPermissions[j]);
            STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
        }
        parrCertificate[i]->toBeSigned.certRequestPermissions = pstCertRequestPermissions;
        
        parrCertificate[i]->toBeSigned.verifyKeyIndicator
                                .present = VerificationKeyIndicator_PR_reconstructionValue;
        parrCertificate[i]->toBeSigned.verifyKeyIndicator
                                .choice.reconstructionValue
                                    .present = EccP256CurvePoint_PR_x_only;
        FILL_WITH_OCTET_STRING(
        parrCertificate[i]->toBeSigned.verifyKeyIndicator
                                .choice.reconstructionValue
                                    .choice.x_only, ucs, 32, ret);
        STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        
        ret = asn_set_add(
        &pstSignedCertificateRequest->signer
                            .choice.certificate.list, parrCertificate[i]);
        STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
    }
    
    pstSignedCertificateRequest->signature
                                .present = Signature_PR_sm2Signature;
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->signature
                    .choice.sm2Signature.r, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->signature
                    .choice.sm2Signature.s, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    char oerbuf[OERBUFSIZE] = { 0 };
    size_t oerlen = 0;
    asn_enc_rval_t ec = oer_encode_to_buffer(&asn_DEF_SignedCertificateRequest,
                                             NULL,
                                             pstSignedCertificateRequest,
                                             oerbuf,
                                             OERBUFSIZE);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode_to_buffer,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    oerlen = ec.encoded;

    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.signedCertificateRequest,
                           oerbuf, 
                           oerlen,
                           ret);
    STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");

    pstSignedAuthenticatedDownloadRequest->content = pstIeee1609Dot2Content;

    /** 测试 */
    FILE* fp = fopen("SignedAuthenticatedDownloadRequest.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_SignedAuthenticatedDownloadRequest,
                    pstSignedAuthenticatedDownloadRequest,
                    write_callback,
                    (void*)fp);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    if (fp) fclose(fp);
    fp = fopen("SignedCertificateRequest.pcdownload.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_SignedCertificateRequest,
                    pstSignedCertificateRequest,
                    write_callback,
                    (void*)fp);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");

    // xml print SignedAuthenticatedDownloadRequest_t
    xer_fprint(stdout, &asn_DEF_SignedAuthenticatedDownloadRequest,
                        pstSignedAuthenticatedDownloadRequest);
    // xml print SignedCertificateRequest_t
    xer_fprint(stdout, &asn_DEF_SignedCertificateRequest, pstSignedCertificateRequest);

    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode pc download encryptedData success ===\n");
    ASN_STRUCT_FREE(asn_DEF_SignedAuthenticatedDownloadRequest, 
                    pstSignedAuthenticatedDownloadRequest);
    ASN_STRUCT_FREE(asn_DEF_SignedCertificateRequest, pstSignedCertificateRequest);
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free pc download encryptedData success ====\n");
    
    
    return ret;
    
}

int decode_SignedAuthenticatedDownloadRequest(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SignedAuthenticatedDownloadRequest_t* pstSignedAuthenticatedDownloadRequest = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SignedAuthenticatedDownloadRequest, 
                      (void**)&pstSignedAuthenticatedDownloadRequest,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SignedAuthenticatedDownloadRequest, 
                        pstSignedAuthenticatedDownloadRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SignedAuthenticatedDownloadRequest_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedAuthenticatedDownloadRequest, 
                    pstSignedAuthenticatedDownloadRequest);
    if (0 == ret) fprintf(stdout, "==== free SignedAuthenticatedDownloadRequest_t success ====\n");
    
    return ret;
}

int encode_SecuredIdCertProvisioningRequest()
{
    int ret = -1;
    
    SecuredIdCertProvisioningRequest_t* pstSecuredIdCertProvisioningRequest = NULL;
    
    pstSecuredIdCertProvisioningRequest = 
                                    calloc(1, sizeof(SecuredIdCertProvisioningRequest_t));
    STOP_IT_IF_ERROR(NULL == pstSecuredIdCertProvisioningRequest, 
                     SecuredIdCertProvisioningRequest_t, 
                     "calloc failed\n");
    // Field: protocolVersion
    pstSecuredIdCertProvisioningRequest->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_encryptedData;
    
    struct RecipientInfo* parrRecipientInfo[XSIZE] = { NULL };
    int i;
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrRecipientInfo[i]) {
            parrRecipientInfo[i] = calloc(1, sizeof(struct RecipientInfo));
            STOP_IT_IF_ERROR(NULL == parrRecipientInfo[i], 
                             RecipientInfo_t,
                             "calloc failed\n");
        }
        parrRecipientInfo[i]->present = RecipientInfo_PR_symmRecipInfo;
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.recipientId, ucs, 8, ret);
        STOP_IT_IF_ERROR(0 != ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
        
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .present = SymmetricCiphertext_PR_sm4Ccm;
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .choice.sm4Ccm.nonce, ucs, 12, ret);
        STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .choice.sm4Ccm.ccmCiphertext, ucs, 32, ret);
        STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");

        ret = asn_set_add(&pstIeee1609Dot2Content->choice.encryptedData.recipients.list,
                          parrRecipientInfo[i]);
        STOP_IT_IF_ERROR(0 != ret, RecipientInfo_t, "asn_set_add failed\n");
    }
    
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .present = SymmetricCiphertext_PR_sm4Ccm;
    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .choice.sm4Ccm.nonce, ucs, 12, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");

    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .choice.sm4Ccm.ccmCiphertext, ucs, 64, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    pstSecuredIdCertProvisioningRequest->content = pstIeee1609Dot2Content;
    
    /** 测试 */
    FILE* fp = fopen("SecuredIdCertProvisioningRequest.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    asn_enc_rval_t ec = oer_encode(&asn_DEF_SecuredIdCertProvisioningRequest,
                    pstSecuredIdCertProvisioningRequest,
                    write_callback,
                    (void*)fp);
    // xml print SecuredIdCertProvisioningRequest_t
    xer_fprint(stdout, &asn_DEF_SecuredIdCertProvisioningRequest,
                        pstSecuredIdCertProvisioningRequest);

    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode ic request success ===\n");
    ASN_STRUCT_FREE(asn_DEF_SecuredIdCertProvisioningRequest, 
                    pstSecuredIdCertProvisioningRequest);
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free ic request success ====\n");
    
    
    return ret; 
}

int decode_SecuredIdCertProvisioningRequest(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SecuredIdCertProvisioningRequest_t* pstSecuredIdCertProvisioningRequest = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SecuredIdCertProvisioningRequest, 
                      (void**)&pstSecuredIdCertProvisioningRequest,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SecuredIdCertProvisioningRequest,
                        pstSecuredIdCertProvisioningRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SecuredIdCertProvisioningRequest_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SecuredIdCertProvisioningRequest, 
                    pstSecuredIdCertProvisioningRequest);

    if (0 == ret) fprintf(stdout, "==== free SecuredIdCertProvisioningRequest_t success ====\n");
    
    return ret;
}

int encode_SignedIdCertProvisioningRequest()
{
    int ret = -1;
    
    SignedIdCertProvisioningRequest_t* pstSignedIdCertProvisioningRequest = NULL;
    
    pstSignedIdCertProvisioningRequest = calloc(1, sizeof(SignedIdCertProvisioningRequest_t));
    STOP_IT_IF_ERROR(NULL == pstSignedIdCertProvisioningRequest, 
                     SignedIdCertProvisioningRequest_t, 
                     "calloc failed\n");
    // Field: protocolVersion
    pstSignedIdCertProvisioningRequest->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_signedCertificateRequest;
    /** 不透明指针 - SignedCertificateRequest */
    struct SignedCertificateRequest* pstSignedCertificateRequest = NULL;
    pstSignedCertificateRequest = calloc(1, sizeof(struct SignedCertificateRequest));
    STOP_IT_IF_ERROR(NULL == pstSignedCertificateRequest, 
                     SignedCertificateRequest_t, 
                     "calloc failed\n");

    pstSignedCertificateRequest->hashId = HashAlgorithm_sm3;
    pstSignedCertificateRequest->tbsRequest
                        .version = ScmsPDUVersion;
    pstSignedCertificateRequest->tbsRequest
                        .content.present = ScmsPDU__content_PR_ee_ra;
    pstSignedCertificateRequest->tbsRequest
                        .content.choice.ee_ra
                            .present = EndEntityRaInterfacePDU_PR_eeRaIdCertProvisioningRequest;
    pstSignedCertificateRequest->tbsRequest
                        .content.choice.ee_ra
                            .choice.eeRaIdCertProvisioningRequest
                                .version = EeRaIdCertReqVersion;
    pstSignedCertificateRequest->tbsRequest
                        .content.choice.ee_ra
                            .choice.eeRaIdCertProvisioningRequest
                                .verify_key_info.seed_key
                                    .present = EccP256CurvePoint_PR_x_only;
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->tbsRequest
                        .content.choice.ee_ra
                            .choice.eeRaIdCertProvisioningRequest
                                .verify_key_info.seed_key
                                    .choice.x_only, ucs, 32, ret);                              
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->tbsRequest
                        .content.choice.ee_ra
                            .choice.eeRaIdCertProvisioningRequest
                                .verify_key_info.expansion, ucs, 16, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");

    pstSignedCertificateRequest->tbsRequest
                        .content.choice.ee_ra
                            .choice.eeRaIdCertProvisioningRequest
                                .resp_enc_key_info.seed_key
                                    .present = EccP256CurvePoint_PR_x_only;
    FILL_WITH_OCTET_STRING(                     
    pstSignedCertificateRequest->tbsRequest
                        .content.choice.ee_ra
                            .choice.eeRaIdCertProvisioningRequest
                                .resp_enc_key_info.seed_key
                                    .choice.x_only, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->tbsRequest
                        .content.choice.ee_ra
                            .choice.eeRaIdCertProvisioningRequest
                                .resp_enc_key_info.expansion, ucs, 16, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");

    pstSignedCertificateRequest->tbsRequest
                        .content.choice.ee_ra
                            .choice.eeRaIdCertProvisioningRequest
                                .common.current_time = time(NULL);
    pstSignedCertificateRequest->tbsRequest
                        .content.choice.ee_ra
                            .choice.eeRaIdCertProvisioningRequest
                                .common.requested_start_time = time(NULL) - 0x2345;

    pstSignedCertificateRequest->signer
                            .present = SignerIdentifier_PR_certificate;
    
    Certificate_t* parrCertificate[XSIZE] = { NULL };
    int i;
    for (i = 0; i < ONESIZE; i++) {
        if (NULL == parrCertificate[i]) {
            parrCertificate[i] = calloc(1, sizeof(Certificate_t));
            STOP_IT_IF_ERROR(NULL == parrCertificate[i], 
                             Certificate_t,
                             "calloc failed\n");
        }
        
        parrCertificate[i]->version = CertificateVersion;
        parrCertificate[i]->type = CertificateType_implicit;
        parrCertificate[i]->issuer.present = IssuerIdentifier_PR_self;
        parrCertificate[i]->issuer.choice.self = HashAlgorithm_sm3;
        parrCertificate[i]->toBeSigned.id.present = CertificateId_PR_none;
        parrCertificate[i]->toBeSigned.id.choice.none = 0;
        FILL_WITH_OCTET_STRING(
        parrCertificate[i]->toBeSigned.cracaId, ucs, 3, ret);
        STOP_IT_IF_ERROR(0 != ret, HashedId3_t, "OCTET_STRING_fromBuf failed\n");
        parrCertificate[i]->toBeSigned.crlSeries = 65513;
        parrCertificate[i]->toBeSigned.validityPeriod.start = time(NULL);
        parrCertificate[i]->toBeSigned.validityPeriod.duration.present = Duration_PR_years;
        parrCertificate[i]->toBeSigned.validityPeriod.duration.choice.years = 16;
        
        struct SequenceOfPsidSsp* pstAppPermissions = NULL;
        pstAppPermissions = calloc(1, sizeof(struct SequenceOfPsidSsp));
        STOP_IT_IF_ERROR(NULL == pstAppPermissions,
                         SequenceOfPsidSsp_t,
                         "calloc failed\n");
        struct PsidSsp* parrPsidSsp[XSIZE] = { NULL };
        int j;
        for (j = 0; j < YSIZE; j++) {
            if (NULL == parrPsidSsp[j]) {
                parrPsidSsp[j] = calloc(1, sizeof(struct PsidSsp));
                STOP_IT_IF_ERROR(NULL == parrPsidSsp[j], PsidSsp_t, "calloc failed\n");
            }
            parrPsidSsp[j]->psid = 100;
            parrPsidSsp[j]->ssp = calloc(1, sizeof(struct ServiceSpecificPermissions));
            STOP_IT_IF_ERROR(NULL == parrPsidSsp[j]->ssp,
                             ServiceSpecificPermissions_t,
                             "calloc failed\n");
            parrPsidSsp[j]->ssp->present = ServiceSpecificPermissions_PR_opaque;
            FILL_WITH_OCTET_STRING(parrPsidSsp[j]->ssp->choice.opaque, ucs, -1, ret);
            STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
            ret = asn_set_add(&pstAppPermissions->list, parrPsidSsp[j]);
            STOP_IT_IF_ERROR(0 != ret, ServiceSpecificPermissions_t, "asn_set_add failed\n");
        }
        parrCertificate[i]->toBeSigned.appPermissions = pstAppPermissions;
        
        struct SequenceOfPsidGroupPermissions* pstCertIssuePermissions = NULL;
        pstCertIssuePermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
        STOP_IT_IF_ERROR(NULL == pstCertIssuePermissions, 
                         SequenceOfPsidGroupPermissions_t, 
                         "calloc failed\n");
        struct PsidGroupPermissions* parrCertIssuePermissions[XSIZE] = { NULL };
        for (j = 0; j < YSIZE; j++) {
            if (NULL == parrCertIssuePermissions[j]) {
                parrCertIssuePermissions[j] = calloc(1, sizeof(struct PsidGroupPermissions));
                STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[j], 
                                 PsidGroupPermissions_t,
                                 "calloc failed\n");
            }
            parrCertIssuePermissions[j]->subjectPermissions.present = SubjectPermissions_PR_all;
            parrCertIssuePermissions[j]->subjectPermissions.choice.all = 0;
            
            if (NULL == parrCertIssuePermissions[j]->minChainLength) {
                parrCertIssuePermissions[j]->minChainLength = calloc(1, sizeof(long));
                STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[j]->minChainLength, 
                                 long_t,
                                 "calloc failed\n");
            }
            *parrCertIssuePermissions[j]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
            
            parrCertIssuePermissions[j]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
            
            if (NULL == parrCertIssuePermissions[j]->eeType) {
                parrCertIssuePermissions[j]->eeType = calloc(1, sizeof(EndEntityType_t));
                STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[j]->eeType, 
                                 EndEntityType_t,
                                 "calloc failed\n");
            }
            if (NULL == parrCertIssuePermissions[j]->eeType->buf) {
                parrCertIssuePermissions[j]->eeType->buf = calloc(1, 1);
                STOP_IT_IF_ERROR(NULL == parrCertIssuePermissions[j]->eeType->buf, 
                                 uint8_t,
                                 "calloc failed\n");
            }
            parrCertIssuePermissions[j]->eeType->size = 1;
            parrCertIssuePermissions[j]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
            parrCertIssuePermissions[j]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
            parrCertIssuePermissions[j]->eeType->bits_unused = 6;
            
            ret = asn_set_add(&pstCertIssuePermissions->list, parrCertIssuePermissions[j]);
            STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
        }
        parrCertificate[i]->toBeSigned.certIssuePermissions = pstCertIssuePermissions;
        
        struct SequenceOfPsidGroupPermissions* pstCertRequestPermissions = NULL;
        pstCertRequestPermissions = calloc(1, sizeof(struct SequenceOfPsidGroupPermissions));
        STOP_IT_IF_ERROR(NULL == pstCertRequestPermissions, 
                         SequenceOfPsidGroupPermissions_t, 
                         "calloc failed\n");
        struct PsidGroupPermissions* parrCertRequestPermissions[XSIZE] = { NULL };
        for (j = 0; j < YSIZE; j++) {
            if (NULL == parrCertRequestPermissions[j]) {
                parrCertRequestPermissions[j] = calloc(1, sizeof(struct PsidGroupPermissions));
                STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[j], 
                                 PsidGroupPermissions_t,
                                 "calloc failed\n");
            }
            parrCertRequestPermissions[j]->subjectPermissions.present = SubjectPermissions_PR_all;
            parrCertRequestPermissions[j]->subjectPermissions.choice.all = 0;
            
            if (NULL == parrCertRequestPermissions[j]->minChainLength) {
                parrCertRequestPermissions[j]->minChainLength = calloc(1, sizeof(long));
                STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[j]->minChainLength, 
                                 long_t,
                                 "calloc failed\n");
            }
            *parrCertRequestPermissions[j]->minChainLength = DEFAULT_MIN_CHAIN_LENGHT;
            
            parrCertRequestPermissions[j]->chainLengthRange = DEFAULT_CHAIN_LENGHT_RANGE;
            
            if (NULL == parrCertRequestPermissions[j]->eeType) {
                parrCertRequestPermissions[j]->eeType = calloc(1, sizeof(EndEntityType_t));
                STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[j]->eeType, 
                                 EndEntityType_t,
                                 "calloc failed\n");
            }
            if (NULL == parrCertRequestPermissions[j]->eeType->buf) {
                parrCertRequestPermissions[j]->eeType->buf = calloc(1, 1);
                STOP_IT_IF_ERROR(NULL == parrCertRequestPermissions[j]->eeType->buf, 
                                 uint8_t,
                                 "calloc failed\n");
            }
            parrCertRequestPermissions[j]->eeType->size = 1;
            parrCertRequestPermissions[j]->eeType->buf[0] |= 1 << (7 - EndEntityType_app);
            parrCertRequestPermissions[j]->eeType->buf[0] |= 1 << (7 - EndEntityType_enrol);
            parrCertRequestPermissions[j]->eeType->bits_unused = 6;
            
            ret = asn_set_add(&pstCertRequestPermissions->list, parrCertRequestPermissions[j]);
            STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
        }
        parrCertificate[i]->toBeSigned.certRequestPermissions = pstCertRequestPermissions;
        
        parrCertificate[i]->toBeSigned.verifyKeyIndicator
                                .present = VerificationKeyIndicator_PR_reconstructionValue;
        parrCertificate[i]->toBeSigned.verifyKeyIndicator
                                .choice.reconstructionValue
                                    .present = EccP256CurvePoint_PR_x_only;
        FILL_WITH_OCTET_STRING(
        parrCertificate[i]->toBeSigned.verifyKeyIndicator
                                .choice.reconstructionValue
                                    .choice.x_only, ucs, 32, ret);
        STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        
        ret = asn_set_add(
        &pstSignedCertificateRequest->signer
                            .choice.certificate.list, parrCertificate[i]);
        STOP_IT_IF_ERROR(0 != ret, PsidGroupPermissions_t, "asn_set_add failed\n");
    }
    
    pstSignedCertificateRequest->signature
                            .present = Signature_PR_sm2Signature;
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->signature
                    .choice.sm2Signature.r, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    FILL_WITH_OCTET_STRING(
    pstSignedCertificateRequest->signature
                    .choice.sm2Signature.s, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    char oerbuf[OERBUFSIZE] = { 0 };
    size_t oerlen = 0;
    asn_enc_rval_t ec = oer_encode_to_buffer(&asn_DEF_SignedCertificateRequest,
                                             NULL,
                                             pstSignedCertificateRequest,
                                             oerbuf,
                                             OERBUFSIZE);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode_to_buffer,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    oerlen = ec.encoded;

    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.signedCertificateRequest,
                           oerbuf, 
                           oerlen,
                           ret);
    STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");
    
    pstSignedIdCertProvisioningRequest->content = pstIeee1609Dot2Content;
    
    /** 测试 */
    FILE* fp = fopen("SignedIdCertProvisioningRequest.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_SignedIdCertProvisioningRequest,
                                     pstSignedIdCertProvisioningRequest,
                                     write_callback,
                                     (void*)fp);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    if (fp) fclose(fp);
    fp = fopen("SignedCertificateRequest.rapseureq.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_SignedCertificateRequest,
                    pstSignedCertificateRequest,
                    write_callback,
                    (void*)fp);
    
    // xml print SignedIdCertProvisioningRequest_t
    xer_fprint(stdout, &asn_DEF_SignedIdCertProvisioningRequest, 
               pstSignedIdCertProvisioningRequest);
    // xml print SignedCertificateRequest_t
    xer_fprint(stdout, &asn_DEF_SignedCertificateRequest, pstSignedCertificateRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode ic request encryptedData success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedIdCertProvisioningRequest,
                    pstSignedIdCertProvisioningRequest);
    ASN_STRUCT_FREE(asn_DEF_SignedCertificateRequest, pstSignedCertificateRequest);
                    
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free ic request encryptedData success ====\n");

    return ret;
}

int decode_SignedIdCertProvisioningRequest(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SignedIdCertProvisioningRequest_t* pstSignedIdCertProvisioningRequest = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SignedIdCertProvisioningRequest, 
                      (void**)&pstSignedIdCertProvisioningRequest,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SignedIdCertProvisioningRequest, 
                        pstSignedIdCertProvisioningRequest);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SignedIdCertProvisioningRequest_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedIdCertProvisioningRequest, 
                    pstSignedIdCertProvisioningRequest);
    if (0 == ret) fprintf(stdout, "==== free SignedIdCertProvisioningRequest_t success ====\n");
    
    return ret;
}

int encode_SecuredIdCertProvisioningAck()
{
    int ret = -1;
    
    SecuredIdCertProvisioningAck_t* pstSecuredIdCertProvisioningAck = NULL;
    
    pstSecuredIdCertProvisioningAck = calloc(1, sizeof(SecuredIdCertProvisioningAck_t));
    STOP_IT_IF_ERROR(NULL == pstSecuredIdCertProvisioningAck, 
                     SecuredIdCertProvisioningAck_t, 
                     "calloc failed\n");
    // Field: protocolVersion
    pstSecuredIdCertProvisioningAck->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_encryptedData;

    struct RecipientInfo* parrRecipientInfo[XSIZE] = { NULL };
    int i;
    for (i = 0; i < XSIZE; i++) {
        if (NULL == parrRecipientInfo[i]) {
            parrRecipientInfo[i] = calloc(1, sizeof(struct RecipientInfo));
            STOP_IT_IF_ERROR(NULL == parrRecipientInfo[i], 
                             RecipientInfo_t,
                             "calloc failed\n");
        }
        parrRecipientInfo[i]->present = RecipientInfo_PR_symmRecipInfo;
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.recipientId, ucs, 8, ret);
        STOP_IT_IF_ERROR(0 != ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
        
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .present = SymmetricCiphertext_PR_sm4Ccm;
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .choice.sm4Ccm.nonce, ucs, 12, ret);
        STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        
        FILL_WITH_OCTET_STRING(
        parrRecipientInfo[i]->choice.symmRecipInfo.encKey
                                        .choice.sm4Ccm.ccmCiphertext, ucs, 32, ret);
        STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");

        ret = asn_set_add(&pstIeee1609Dot2Content->choice.encryptedData.recipients.list,
                          parrRecipientInfo[i]);
        STOP_IT_IF_ERROR(0 != ret, RecipientInfo_t, "asn_set_add failed\n");
    }
    
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .present = SymmetricCiphertext_PR_sm4Ccm;
    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .choice.sm4Ccm.nonce, ucs, 12, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");

    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2Content->choice.encryptedData.ciphertext
                                            .choice.sm4Ccm.ccmCiphertext, ucs, 64, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    pstSecuredIdCertProvisioningAck->content = pstIeee1609Dot2Content;

    /** 测试 */
    FILE* fp = fopen("SecuredIdCertProvisioningAck.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    asn_enc_rval_t ec = oer_encode(&asn_DEF_SecuredIdCertProvisioningAck,
                                    pstSecuredIdCertProvisioningAck,
                                    write_callback,
                                    (void*)fp);
    // xml print SecuredIdCertProvisioningAck_t
    xer_fprint(stdout, &asn_DEF_SecuredIdCertProvisioningAck,
                        pstSecuredIdCertProvisioningAck);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode ic ack success ===\n");

    ASN_STRUCT_FREE(asn_DEF_SecuredIdCertProvisioningAck, 
                    pstSecuredIdCertProvisioningAck);
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free ic ack success ====\n");
    
    return ret;
}

int decode_SecuredIdCertProvisioningAck(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SecuredIdCertProvisioningAck_t* pstSecuredIdCertProvisioningAck = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SecuredIdCertProvisioningAck, 
                      (void**)&pstSecuredIdCertProvisioningAck,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SecuredIdCertProvisioningAck, 
                       pstSecuredIdCertProvisioningAck);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SecuredIdCertProvisioningAck_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SecuredIdCertProvisioningAck, 
                    pstSecuredIdCertProvisioningAck);
    
    if (0 == ret) fprintf(stdout, "==== free SecuredIdCertProvisioningAck_t success ====\n");
    
    return ret;
}

int encode_SignedIdCertProvisioningAck()
{
    int ret = -1;
    
    SignedIdCertProvisioningAck_t* pstSignedIdCertProvisioningAck = NULL;
    
    pstSignedIdCertProvisioningAck = calloc(1, sizeof(SignedIdCertProvisioningAck_t));
    STOP_IT_IF_ERROR(NULL == pstSignedIdCertProvisioningAck, 
                     SignedIdCertProvisioningAck_t, 
                     "calloc failed\n");
    // Field: protocolVersion
    pstSignedIdCertProvisioningAck->protocolVersion = ProtocolVersion;
    // Field: Ieee1609Dot2Content (with components)
    struct Ieee1609Dot2Content* pstIeee1609Dot2Content = NULL;
    pstIeee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Content, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2Content->present = Ieee1609Dot2Content_PR_signedData;

    struct SignedData* pstSignedData = NULL;
    pstSignedData = calloc(1, sizeof(struct SignedData));
    STOP_IT_IF_ERROR(NULL == pstSignedData,
                     SignedData_t, 
                     "calloc failed\n");
    
    pstSignedData->hashId = HashAlgorithm_sm3;
    
    struct ToBeSignedData* pstToBeSignedData = NULL;
    pstToBeSignedData = calloc(1, sizeof(struct ToBeSignedData));
    STOP_IT_IF_ERROR(NULL == pstToBeSignedData, 
                     ToBeSignedData_t, 
                     "calloc failed\n");
                     
    struct SignedDataPayload* pstSignedDataPayload = NULL;
    pstSignedDataPayload = calloc(1, sizeof(struct SignedDataPayload));
    STOP_IT_IF_ERROR(NULL == pstSignedDataPayload, 
                     SignedDataPayload_t, 
                     "calloc failed\n");
    
    struct Ieee1609Dot2Data* pstIeee1609Dot2Data = NULL;
    pstIeee1609Dot2Data = calloc(1, sizeof(struct Ieee1609Dot2Data));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2Data, 
                     Ieee1609Dot2Data_t, 
                     "calloc failed\n");
    
    pstIeee1609Dot2Data->protocolVersion = ProtocolVersion;
    
    struct Ieee1609Dot2Content* pstIeee1609Dot2ContentUnsecuredData = NULL;
    pstIeee1609Dot2ContentUnsecuredData = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pstIeee1609Dot2ContentUnsecuredData, 
                     Ieee1609Dot2Content_t, 
                     "calloc failed\n");
    pstIeee1609Dot2ContentUnsecuredData->present = Ieee1609Dot2Content_PR_unsecuredData;
    
    /** 不透明指针 - ScopedIdCertProvisioningAck */
    ScopedIdCertProvisioningAck_t* pstScopedIdCertProvisioningAck = NULL;
    pstScopedIdCertProvisioningAck = calloc(1, sizeof(ScopedIdCertProvisioningAck_t));
    STOP_IT_IF_ERROR(NULL == pstScopedIdCertProvisioningAck, 
                     ScopedIdCertProvisioningAck_t, 
                     "calloc failed\n");
    pstScopedIdCertProvisioningAck->version = ScmsPDUVersion;
    pstScopedIdCertProvisioningAck->content
                            .present = ScmsPDU__content_PR_ee_ra;
    pstScopedIdCertProvisioningAck->content
                            .choice.ee_ra
                                .present = EndEntityRaInterfacePDU_PR_raEeIdCertProvisioningAck;
    pstScopedIdCertProvisioningAck->content
                            .choice.ee_ra
                                .choice.raEeIdCertProvisioningAck
                                    .version = RaPseCertAckVersion;
    FILL_WITH_OCTET_STRING(
    pstScopedIdCertProvisioningAck->content
                            .choice.ee_ra
                                .choice.raEeIdCertProvisioningAck
                                    .requestHash, ucs, 8, ret);
    STOP_IT_IF_ERROR(0 != ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
    
    pstScopedIdCertProvisioningAck->content
                            .choice.ee_ra
                                .choice.raEeIdCertProvisioningAck
                                    .reply.present = RaEePseudonymCertProvisioningAck__reply_PR_ack;
    pstScopedIdCertProvisioningAck->content
                            .choice.ee_ra
                                .choice.raEeIdCertProvisioningAck
                                    .reply.choice.ack
                                        .certDLTime = time(NULL);
    FILL_WITH_OCTET_STRING(
    pstScopedIdCertProvisioningAck->content
                            .choice.ee_ra
                                .choice.raEeIdCertProvisioningAck
                                    .reply.choice.ack
                                        .certDLURL, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
    
    char oerbuf[OERBUFSIZE] = { 0 };
    size_t oerlen = 0;
    asn_enc_rval_t ec = oer_encode_to_buffer(&asn_DEF_ScopedIdCertProvisioningAck,
                                             NULL,
                                             pstScopedIdCertProvisioningAck,
                                             oerbuf,
                                             OERBUFSIZE);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode_to_buffer,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    oerlen = ec.encoded;
    
    FILL_WITH_OCTET_STRING(
    pstIeee1609Dot2ContentUnsecuredData->choice.unsecuredData,
            oerbuf,
            oerlen,
            ret);
    STOP_IT_IF_ERROR(0 != ret, Opaque_t, "OCTET_STRING_fromBuf failed\n");
    
    pstIeee1609Dot2Data->content = pstIeee1609Dot2ContentUnsecuredData;
    
    pstSignedDataPayload->data = pstIeee1609Dot2Data;
    
    // pstSignedDataPayload->extDataHash = ... // do nothing
    
    pstToBeSignedData->payload = pstSignedDataPayload;
    
    pstToBeSignedData->headerInfo.psid = PsidValue;     // data

    pstSignedData->tbsData = pstToBeSignedData;
    
    pstSignedData->signer.present = SignerIdentifier_PR_self;
    pstSignedData->signer.choice.self = 0;
    
    pstSignedData->signature
                    .present = Signature_PR_sm2Signature;
    
    FILL_WITH_OCTET_STRING(
    pstSignedData->signature
                    .choice.sm2Signature.r, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    FILL_WITH_OCTET_STRING(
    pstSignedData->signature
                    .choice.sm2Signature.s, ucs, 32, ret);
    STOP_IT_IF_ERROR(0 != ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    pstIeee1609Dot2Content->choice.signedData = pstSignedData;
    
    pstSignedIdCertProvisioningAck->content = pstIeee1609Dot2Content;
    
    /** 测试 */
    FILE *fp = fopen("SignedIdCertProvisioningAck.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_SignedIdCertProvisioningAck,
                     pstSignedIdCertProvisioningAck,
                     write_callback,
                     (void*)fp);
    STOP_IT_IF_ERROR(-1 == ec.encoded, oer_encode,
                     "%d ecode(%d): %s\n", 
                     __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
                     
    if (fp) fclose(fp);
    fp = fopen("ScopedIdCertProvisioningAck.coer", "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    ec = oer_encode(&asn_DEF_ScopedIdCertProvisioningAck,
                    pstScopedIdCertProvisioningAck,
                    write_callback,
                    (void*)fp);
    // xml print SignedIdCertProvisioningAck_t
    xer_fprint(stdout, &asn_DEF_SignedIdCertProvisioningAck,
                        pstSignedIdCertProvisioningAck);
    // xml print ScopedIdCertProvisioningAck_t
    xer_fprint(stdout, &asn_DEF_ScopedIdCertProvisioningAck, 
                        pstScopedIdCertProvisioningAck);
    printf("\n");
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== encode ic ack success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedIdCertProvisioningAck, pstSignedIdCertProvisioningAck);
    ASN_STRUCT_FREE(asn_DEF_ScopedIdCertProvisioningAck, pstScopedIdCertProvisioningAck);
    
    if (fp) fclose(fp);

    if (0 == ret) fprintf(stdout, "==== free ic ack success ====\n");
    
    return ret;
}

int decode_SignedIdCertProvisioningAck(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    SignedIdCertProvisioningAck_t* pstSignedIdCertProvisioningAck = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_SignedIdCertProvisioningAck, 
                      (void**)&pstSignedIdCertProvisioningAck,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_SignedIdCertProvisioningAck, pstSignedIdCertProvisioningAck);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode SignedIdCertProvisioningAck_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_SignedIdCertProvisioningAck, pstSignedIdCertProvisioningAck);
    if (0 == ret) fprintf(stdout, "==== free SignedIdCertProvisioningAck_t success ====\n");
    
    return ret; 
}

int decode_ScopedIdCertProvisioningAck(const char* buf, size_t size)
{
    int ret = -1;
    asn_dec_rval_t rval;
    ScopedIdCertProvisioningAck_t* pstScopedIdCertProvisioningAck = NULL;
    
    rval = oer_decode(0, 
                      &asn_DEF_ScopedIdCertProvisioningAck, 
                      (void**)&pstScopedIdCertProvisioningAck,
                      buf, 
                      size);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            " Broken Type encoding at byte %ld\n", (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_ScopedIdCertProvisioningAck, pstScopedIdCertProvisioningAck);
    
    ret = 0;
cleanup:
    if (0 == ret) fprintf(stdout, "=== decode ScopedIdCertProvisioningAck_t success ===\n");
    
    ASN_STRUCT_FREE(asn_DEF_ScopedIdCertProvisioningAck, pstScopedIdCertProvisioningAck);
    if (0 == ret) fprintf(stdout, "==== free ScopedIdCertProvisioningAck_t success ====\n");
    
    return ret;
}

// 有参数传入时解码，没有参数传入时编码
#define USAGE                                   \
    "./encode\n\n"                              \
    "or\n\n"                                    \
    "./decode <input coer file> <type>\n"       \
    "  type:\n"                                 \
    "     1 - SignedEeEnrollmentCertRequest   ec 请求\n"                        \
    "     2 - SignedCertificateRequest        ec 请求中序列化串结构体\n"        \
    "     3 - SignedEeEnrollmentCertResponse  ec 响应\n"                        \
    "     4 - ScopedEeEnrollmentCertResponse  ec 响应中序列化串结构体\n"        \
    "     5 - SecuredRACertRequest            ra 请求\n"                        \
    "     6 - ScopedEeRaCertRequest           ra 请求中序列化串结构体\n"        \
    "     7 - SecuredRACertResponse           ra 响应\n"                        \
    "     8 - ScopedRaEeCertResponse          ra 响应中序列化串结构体之一\n"    \
    "     9 - ScopedElectorEndorsement        ra 响应中序列化串结构体之二\n"    \
    "    10 - CrlContents                     ra 响应中序列化串结构体之三\n"    \
    "    11 - SecuredPseudonymCertProvisioningRequest   pc 申请\n"              \
    "    12 - SignedPseudonymCertProvisioningRequest    pc 申请中的加密部分\n"  \
    "    13 - SecuredPseudonymCertProvisioningAck       pc 确认\n"              \
    "    14 - SignedPseudonymCertProvisioningAck        pc 确认中的加密部分\n"  \
    "    15 - ScopedPseudonymCertProvisioningAck        pc 确认中加密部分明文中序列化串结构体\n"  \
    "    16 - SecuredAuthenticatedDownloadRequest       pc 下载请求\n"          \
    "    17 - SignedAuthenticatedDownloadRequest        pc 下载请求中的加密部分\n"                \
    "    18 - SecuredIdCertProvisioningRequest          ic 请求\n"              \
    "    19 - SignedIdCertProvisioningRequest           ic 请求中的加密部分\n"  \
    "    20 - SecuredIdCertProvisioningAck              ic 确认\n"              \
    "    21 - SignedIdCertProvisioningAck               ic 确认中的加密部分\n"  \
    "    22 - ScopedIdCertProvisioningAck               ic 确认中加密部分明文中序列化串结构体\n"  \
    "\n"
    
int main(int argc, char* argv[])
{
    int ret = -1;
    int encode = 0;
    if (argc == 1) {
        encode = 1;
        printf("execute asn1 encode ...\n");
    } else if (argc == 3) {
        encode = 0;
        printf("execute asn1 decode ...\n");
    } else {
        printf(USAGE);
        return -1;
    }
    
    int  i;
    FILE* fin = NULL;
    
    if (encode == 1) {
        for (i = 0; i < 1; i++) {
            encode_SignedEeEnrollmentCertRequest();              // playground check error
            // encode_SignedEeEnrollmentCertResponse();             // ok
            // encode_SecuredRACertRequest();                       // ok
            // encode_SecuredRACertResponse();                      // ok
            // encode_SecuredPseudonymCertProvisioningRequest();    // ok
            // encode_SignedPseudonymCertProvisioningRequest();     // ok
            // encode_SecuredPseudonymCertProvisioningAck();        // ok
            // encode_SignedPseudonymCertProvisioningAck();         // ok
            // encode_SecuredAuthenticatedDownloadRequest();        // ok
            // encode_SignedAuthenticatedDownloadRequest();         // ok
            // encode_SecuredIdCertProvisioningRequest();           // ok
            // encode_SignedIdCertProvisioningRequest();            // ok
            // encode_SecuredIdCertProvisioningAck();               // ok
            // encode_SignedIdCertProvisioningAck();
        }
    }
    
    if (encode == 0) {
        unsigned char buf[4096] = { 0 };
        size_t bsize = 0, rsize = 0;
        
        fin = fopen(argv[1], "rb");
        STOP_IT_IF_ERROR(NULL == fin, fopen, strerror(errno));
        
        fseek(fin, 0, SEEK_END);
        bsize = ftell(fin);
        fseek(fin, 0, SEEK_SET);
        
        rsize = fread(buf, 1, sizeof(buf), fin);
        STOP_IT_IF_ERROR(rsize <= 0, fread, strerror(errno));
        
        STOP_IT_IF_ERROR(bsize != rsize, "", "binary file size error(%ld != %ld)\n", bsize, rsize);
        
        int decode_type = atoi(argv[2]);
        
        for (i = 0; i < 1; i++) {
            if (decode_type == 1) {
                decode_SignedEeEnrollmentCertRequest(buf, rsize);
            } else if (decode_type == 2) {
                decode_SignedCertificateRequest(buf, rsize);
            } else if (decode_type == 3) {
                decode_SignedEeEnrollmentCertResponse(buf, rsize);
            } else if (decode_type == 4) {
                decode_ScopedEeEnrollmentCertResponse(buf, rsize);
            } else if (decode_type == 5) {
                decode_SecuredRACertRequest(buf, rsize);
            } else if (decode_type == 6) {
                decode_ScopedEeRaCertRequest(buf, rsize);
            } else if (decode_type == 7) {
                decode_SecuredRACertResponse(buf, rsize);
            } else if (decode_type == 8) {
                decode_ScopedRaEeCertResponse(buf, rsize);
            } else if (decode_type == 9) {
                decode_ScopedElectorEndorsement(buf, rsize);
            } else if (decode_type == 10) {
                decode_CrlContents(buf, rsize);
            } else if (decode_type == 11) {
                decode_SecuredPseudonymCertProvisioningRequest(buf, rsize);
            } else if (decode_type == 12) {
                decode_SignedPseudonymCertProvisioningRequest(buf, rsize);
            } else if (decode_type == 13) {
                decode_SecuredPseudonymCertProvisioningAck(buf, rsize);
            } else if (decode_type == 14) {
                decode_SignedPseudonymCertProvisioningAck(buf, rsize);
            } else if (decode_type == 15) {
                decode_ScopedPseudonymCertProvisioningAck(buf, rsize);
            } else if (decode_type == 16) {
                decode_SecuredAuthenticatedDownloadRequest(buf, rsize);
            } else if (decode_type == 17) {
                decode_SignedAuthenticatedDownloadRequest(buf, rsize);
            } else if (decode_type == 18) {
                decode_SecuredIdCertProvisioningRequest(buf, rsize);
            } else if (decode_type == 19) {
                decode_SignedIdCertProvisioningRequest(buf, rsize);
            } else if (decode_type == 20) {
                decode_SecuredIdCertProvisioningAck(buf, rsize);
            } else if (decode_type == 21) {
                decode_SignedIdCertProvisioningAck(buf, rsize);
            } else if (decode_type == 22) {
                decode_ScopedIdCertProvisioningAck(buf, rsize);
            }
        }
    }

    ret = 0;
cleanup:

    if (fin) fclose(fin);
    
    return ret;
}