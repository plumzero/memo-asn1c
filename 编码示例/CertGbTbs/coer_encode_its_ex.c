#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include "Certificate.h"

#define VERSION                 2

#define X_SIZE                  4
#define Y_SIZE                  3
#define Z_SIZE                  2

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

/**
 * 本测试中有 asn_ulong2INTEGER INTEGER_t
 */

static const unsigned int uinone = 0;
static const unsigned int ui_time_end = 0;
static const unsigned long long ull_its_aid = 0x98765432101;

static const unsigned char digest_s[8] = {
                                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
                            };
static const unsigned char subjectname_s[8] = {
                                0x21, 0x21, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28
                            };
static const unsigned char eccpoint_x_s[32] = {
                                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            };
static const unsigned char eccpoint_y_s[32] = {
                                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            };

static const unsigned char service_specific_permissions_s[] = {     // 只取前 16 个字节测试
                            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
                            'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
                        };

static int write_callback(const void *buffer, size_t size, void *app_key)
{
    FILE *fp = app_key;
    size_t wrote = fwrite(buffer, 1, size, fp);
    return (wrote == size) ? 0 : -1;
}

int main(int argc, char *argv[]) 
{
    int RET = -1, _ret;
    asn_enc_rval_t ec;
    FILE *fp = NULL;
    unsigned char buf[1024] = { 0 };
    size_t rsize;
    size_t i, j, k;
    
    struct Certificate* pst_certificate = NULL;
    struct PublicEncryptionKey* pst_public_encryption_key = NULL;
    struct SequenceOfitsAidSspList  *pst_seqof_its_aid_ssp_list = NULL;
    struct ItsAidSsp *psts_its_aid_ssp[X_SIZE] = { NULL };
    
    if (argc < 2) {
        printf("./exe <output coer file>\n");
        return -1;
    }

    pst_certificate = calloc(1, sizeof(struct Certificate));
    STOP_IT_IF_ERROR(NULL == pst_certificate, Certificate_t, "calloc failed\n");
    // 证书编码
    // version
    pst_certificate->version = VERSION;
    // issuer id
    pst_certificate->issuerId.present = IssuerId_PR_certificateDigest;
    switch (pst_certificate->issuerId.present) {
    case IssuerId_PR_self:
        pst_certificate->issuerId.choice.self = uinone;
        break;
    case IssuerId_PR_certificateDigest:
        pst_certificate->issuerId.choice.certificateDigest.algorithm = HashAlgorithm_sgdsm3;
        FILL_WITH_OCTET_STRING(pst_certificate->issuerId.choice.certificateDigest.digest, digest_s, 8, _ret);
        STOP_IT_IF_ERROR(0 != _ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
        break;
    default:
        LOG_ERR(IssuerId_PR, "no matched value\n");
        goto cleanup;
    }
    // tbs cert
    pst_certificate->tbs.subjectInfo.subjectType = SubjectType_authorizationTicket;
    FILL_WITH_OCTET_STRING(pst_certificate->tbs.subjectInfo.subjectName, subjectname_s, 8, _ret); 
    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    pst_certificate->tbs.subjectAttributes.verificationKey.curve = EccCurve_sgdsm2;
    pst_certificate->tbs.subjectAttributes.verificationKey.key.present = ECCPoint_PR_uncompressed;
    switch (pst_certificate->tbs.subjectAttributes.verificationKey.key.present) {
    case ECCPoint_PR_x_only:
        FILL_WITH_OCTET_STRING(pst_certificate->tbs.subjectAttributes.verificationKey.key.choice.x_only, 
                                                                                    eccpoint_x_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        break;
    case ECCPoint_PR_fill:
        pst_certificate->tbs.subjectAttributes.verificationKey.key.choice.fill = uinone;
        break;
    case ECCPoint_PR_compressed_y_0:
        FILL_WITH_OCTET_STRING(pst_certificate->tbs.subjectAttributes.verificationKey.key.choice.compressed_y_0, 
                                                                                    eccpoint_x_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        break;
    case ECCPoint_PR_compressed_y_1:
        FILL_WITH_OCTET_STRING(pst_certificate->tbs.subjectAttributes.verificationKey.key.choice.compressed_y_1, 
                                                                                    eccpoint_y_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");   
        break;
    case ECCPoint_PR_uncompressed:
        FILL_WITH_OCTET_STRING(pst_certificate->tbs.subjectAttributes.verificationKey.key.choice.uncompressed.x, 
                                                                                    eccpoint_x_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        FILL_WITH_OCTET_STRING(pst_certificate->tbs.subjectAttributes.verificationKey.key.choice.uncompressed.y, 
                                                                                    eccpoint_y_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        break;
    default:
        LOG_ERR(ECCPoint_PR, "no matched value\n");
        goto cleanup;
    }
    // EX TbsCert SubjectAttributes PublicEncryptionKey
    pst_public_encryption_key = calloc(1, sizeof(struct PublicEncryptionKey));
    STOP_IT_IF_ERROR(NULL == pst_public_encryption_key, PublicEncryptionKey_t, "calloc failed\n");
    pst_public_encryption_key->supportedSymmAlg = SymmetricAlgorithm_sgdsm4cbc;
    pst_public_encryption_key->eccCurve = EccCurve_sgdsm2;
    pst_public_encryption_key->publicKey.present = ECCPoint_PR_x_only;
    switch (pst_public_encryption_key->publicKey.present) {
    case ECCPoint_PR_x_only:
        FILL_WITH_OCTET_STRING(pst_public_encryption_key->publicKey.choice.x_only, eccpoint_x_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        break;
    case ECCPoint_PR_fill:
        pst_public_encryption_key->publicKey.choice.fill = uinone;
        break;
    case ECCPoint_PR_compressed_y_0:
        FILL_WITH_OCTET_STRING(pst_public_encryption_key->publicKey.choice.compressed_y_0, 
                                                                                    eccpoint_x_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        break;
    case ECCPoint_PR_compressed_y_1:
        FILL_WITH_OCTET_STRING(pst_public_encryption_key->publicKey.choice.compressed_y_1, 
                                                                                    eccpoint_y_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");   
        break;
    case ECCPoint_PR_uncompressed:
        FILL_WITH_OCTET_STRING(pst_public_encryption_key->publicKey.choice.uncompressed.x, 
                                                                                    eccpoint_x_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        FILL_WITH_OCTET_STRING(pst_public_encryption_key->publicKey.choice.uncompressed.y, 
                                                                                    eccpoint_y_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        break;
    default:
        LOG_ERR(ECCPoint_PR, "no matched value\n");
        goto cleanup;
    }
    pst_certificate->tbs.subjectAttributes.encryptionKey = pst_public_encryption_key;
    // EX TbsCert SubjectAttributes SequenceOfitsAidSspList
    pst_seqof_its_aid_ssp_list = calloc(1, sizeof(struct SequenceOfitsAidSspList));
    STOP_IT_IF_ERROR(NULL == pst_seqof_its_aid_ssp_list, SequenceOfitsAidSspList_t, "calloc failed\n");
    for (i = 0; i < X_SIZE; i++) {
        if (NULL == psts_its_aid_ssp[i]) {
            psts_its_aid_ssp[i] = calloc(1, sizeof(struct ItsAidSsp));
            STOP_IT_IF_ERROR(NULL == psts_its_aid_ssp[i], ItsAidSsp_t, "calloc failed\n");
        }
        _ret = asn_ulong2INTEGER(&psts_its_aid_ssp[i]->itsAid, ull_its_aid);
        STOP_IT_IF_ERROR(0 != _ret, ItsAid_t, "asn_ulong2INTEGER failed\n");        
        FILL_WITH_OCTET_STRING(psts_its_aid_ssp[i]->serviceSpecificPermissions, service_specific_permissions_s, 16, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        _ret = asn_set_add(&pst_seqof_its_aid_ssp_list->list, psts_its_aid_ssp[i]);
        STOP_IT_IF_ERROR(0 != _ret, ItsAidSsp_t, "asn_set_add failed\n");
    }
    pst_certificate->tbs.subjectAttributes.itsAidSspList = pst_seqof_its_aid_ssp_list;
    
    pst_certificate->tbs.validityRestrictions.validityPeriod.present = ValidityPeriod_PR_timeEnd;
    switch (pst_certificate->tbs.validityRestrictions.validityPeriod.present) {
    case ValidityPeriod_PR_timeEnd:
        pst_certificate->tbs.validityRestrictions.validityPeriod.choice.timeEnd = ui_time_end;
        break;
    case ValidityPeriod_PR_timeStartAndEnd:
        pst_certificate->tbs.validityRestrictions.validityPeriod.choice.timeStartAndEnd.startValidity = 0x1234;
        pst_certificate->tbs.validityRestrictions.validityPeriod.choice.timeStartAndEnd.endValidity = 0x5678;
        break;
    default:
        LOG_ERR(ValidityPeriod_PR, "no matched value\n");
        goto cleanup;
    }
    // signature
    pst_certificate->signature.curve = EccCurve_sgdsm2;
    pst_certificate->signature.r.present = ECCPoint_PR_x_only;
    switch (pst_certificate->signature.r.present) {
    case ECCPoint_PR_x_only:
        FILL_WITH_OCTET_STRING(pst_certificate->signature.r.choice.x_only, eccpoint_x_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        break;
    case ECCPoint_PR_fill:
        pst_certificate->signature.r.choice.fill = uinone;
        break;
    case ECCPoint_PR_compressed_y_0:
        FILL_WITH_OCTET_STRING(pst_certificate->signature.r.choice.compressed_y_0, eccpoint_x_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        break;
    case ECCPoint_PR_compressed_y_1:
        FILL_WITH_OCTET_STRING(pst_certificate->signature.r.choice.compressed_y_1, eccpoint_y_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");   
        break;
    case ECCPoint_PR_uncompressed:
        FILL_WITH_OCTET_STRING(pst_certificate->signature.r.choice.uncompressed.x, eccpoint_x_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        FILL_WITH_OCTET_STRING(pst_certificate->signature.r.choice.uncompressed.y, eccpoint_y_s, 32, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        break;
    default:
        LOG_ERR(ECCPoint_PR, "no matched value\n");
        goto cleanup;
    }
    FILL_WITH_OCTET_STRING(pst_certificate->signature.s, eccpoint_y_s, 32, _ret);
    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    
    fp = fopen(argv[1], "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    // 编码
    ec = oer_encode(&asn_DEF_Certificate, pst_certificate, write_callback, (void*)fp);
    STOP_IT_IF_ERROR(1 == ec.encoded, oer_encode, "%d ecode(%d): %s\n", 
                                            __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    xer_fprint(stdout, &asn_DEF_Certificate, pst_certificate);
    fprintf(stdout, "\n");
    // 二进制文件打印
    if (fp) fclose(fp);
    fp = fopen(argv[1], "rb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    rsize = fread(buf, 1, sizeof(buf), fp);
    STOP_IT_IF_ERROR(rsize == 0, fread, strerror(errno));
    for (i = 0, j = 0; i < rsize;) {
        fprintf(stdout, "%02X", buf[i]);
        if (0 == (++i % 4)) { 
            fprintf(stdout, " "); 
            if (0 == (++j % 8)) fprintf(stdout, "\n");
        }       
    }
    printf("\n");
    
    RET = 0;
cleanup:
    if (0 == RET) fprintf(stdout, "=== encode success ===\n");
    else fprintf(stdout, "failed\n");
    
    if (fp) fclose(fp);
      
    ASN_STRUCT_FREE(asn_DEF_Certificate, pst_certificate); 
    
    // 在这里, ASN_STRUCT_FREE_CONTENTS_ONLY + free 等价于 ASN_STRUCT_FREE
    // ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, pst_certificate);
    // if (pst_certificate) free(pst_certificate);
    
    // 在这里, ASN_STRUCT_RESET + free 等价于 ASN_STRUCT_FREE
    // ASN_STRUCT_RESET(asn_DEF_Certificate, pst_certificate);
    // if (pst_certificate) free(pst_certificate);
    
    if (0 == RET) fprintf(stdout, "==== free success ====\n");
    else fprintf(stdout, "failed\n");
    
    return RET;
}
