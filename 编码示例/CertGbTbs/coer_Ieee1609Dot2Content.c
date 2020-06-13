#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include "Ieee1609Dot2Content.h"

#define VERSION                 2

#define X_SIZE                  4

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

static const unsigned int uinone = 0;
static const unsigned int uitime = 0;

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


static int write_callback(const void *buffer, size_t size, void *app_key)
{
    FILE *fp = app_key;
    size_t wrote = fwrite(buffer, 1, size, fp);
    return (wrote == size) ? 0 : -1;
}

/// cc -o st2coer -I. *.c -D_DEFAULT_SOURCE -g -O0

/// 暂只作编码

int main(int argc, char *argv[]) 
{
    int RET = -1, _ret;
    asn_enc_rval_t ec;
    FILE *fp = NULL;
    unsigned char buf[1024] = { 0 };
    size_t rsize;
    size_t i, j, k;

    struct Ieee1609Dot2Content* pst_Ieee1609Dot2Content = NULL;
    struct RecipientInfo* pst_RecipientInfo[X_SIZE] = { NULL };
        
    if (argc < 2) {
        printf("./exe <output coer file>\n");
        return -1;
    }
    
    pst_Ieee1609Dot2Content = calloc(1, sizeof(struct Ieee1609Dot2Content));
    STOP_IT_IF_ERROR(NULL == pst_Ieee1609Dot2Content, Ieee1609Dot2Content_t, "calloc failed\n");
    
////////////////////  新加部分 begin
    pst_Ieee1609Dot2Content->choice.encryptedData.ciphertext.present = SymmetricCiphertext_PR_sgdsm4;
    FILL_WITH_OCTET_STRING(pst_Ieee1609Dot2Content->choice.encryptedData.ciphertext.choice.sgdsm4.iv, 
                                                                  eccpoint_x_s, 16, _ret);
    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
    FILL_WITH_OCTET_STRING(pst_Ieee1609Dot2Content->choice.encryptedData.ciphertext.choice.sgdsm4.ciphertext,
                                                                  eccpoint_y_s, 31, _ret);
    STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
////////////////////  新加部分 end

    pst_Ieee1609Dot2Content->present = Ieee1609Dot2Content_PR_encryptedData;
    for (i = 0; i < X_SIZE; i++) {
        if (NULL == pst_RecipientInfo[i]) {
            pst_RecipientInfo[i] = calloc(1, sizeof(struct RecipientInfo));
            STOP_IT_IF_ERROR(NULL == pst_RecipientInfo[i], RecipientInfo_t, "calloc failed\n");
        }
        pst_RecipientInfo[i]->present = RecipientInfo_PR_rekRecipInfo;
        FILL_WITH_OCTET_STRING(pst_RecipientInfo[i]->choice.rekRecipInfo.recipientId, digest_s, 8, _ret);
        STOP_IT_IF_ERROR(0 != _ret, HashedId8_t, "OCTET_STRING_fromBuf failed\n");
        FILL_WITH_OCTET_STRING(pst_RecipientInfo[i]->choice.rekRecipInfo.encKey, eccpoint_x_s, 10 + i, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        _ret = asn_set_add(&pst_Ieee1609Dot2Content->choice.encryptedData.recipients.list, pst_RecipientInfo[i]);
        STOP_IT_IF_ERROR(0 != _ret, RecipientInfo_t, "asn_set_add failed\n");
    }
    fp = fopen(argv[1], "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    // 编码
    ec = oer_encode(&asn_DEF_Ieee1609Dot2Content, pst_Ieee1609Dot2Content, write_callback, (void*)fp);
    STOP_IT_IF_ERROR(1 == ec.encoded, oer_encode, "%d ecode(%d): %s\n", 
                                            __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    
    xer_fprint(stdout, &asn_DEF_Ieee1609Dot2Content, pst_Ieee1609Dot2Content);
    fprintf(stdout, "\n");
    
    RET = 0;
cleanup:
    if (0 == RET) fprintf(stdout, "=== encode success ===\n");
    else fprintf(stdout, "failed\n");
    
    if (fp) fclose(fp);
    
    ASN_STRUCT_FREE(asn_DEF_Ieee1609Dot2Content, pst_Ieee1609Dot2Content);
    
    if (0 == RET) fprintf(stdout, "==== free success ====\n");
    else fprintf(stdout, "failed\n");
    
    return RET;
}
