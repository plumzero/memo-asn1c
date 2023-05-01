#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include "Crl.h"

#define VERSION                 2
#define ONLY_ONE                1
#define X_SIZE                  6

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
static const unsigned int uitime2 = 1000;
static const unsigned int uione = 1;

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
static const unsigned char revoke_info_id_s[10] = {
                                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x00
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
    asn_dec_rval_t rval;
    FILE *fp = NULL;
    unsigned char buf[1024] = { 0 };
    unsigned char ocbuf[64] = { 0 };
    size_t rsize, bsize;
    size_t i, j, k;
        
    if (argc < 2) {
        printf("./exe <output coer file>\n");
        return -1;
    }

    struct ToBeSignedCrl* pst_to_be_signed_crl = NULL;
    struct ToBeSignedCrl* pst_to_be_signed_crl_de = NULL;
    struct RevokeInfo* pst_revoke_info[X_SIZE] = { NULL };
    struct RevokeInfo* pst_revoke_info_de[X_SIZE] = { NULL };
    struct ToBeSignedCrl *pst_ToBeSignedCrl = NULL;
    // struct ToBeSignedCrl to_be_signed_crl;
    
    pst_to_be_signed_crl = calloc(1, sizeof(struct ToBeSignedCrl));
    STOP_IT_IF_ERROR(NULL == pst_to_be_signed_crl, ToBeSignedCrl_t, "calloc failed\n");
    pst_to_be_signed_crl->crlSerial = 0x123456;
    pst_to_be_signed_crl->issueDate = 0x567890;
    pst_to_be_signed_crl->nextCrl = 0x123456;
    for (i = 0; i < X_SIZE; i++) {
        if (NULL == pst_revoke_info[i]) {
            pst_revoke_info[i] = calloc(1, sizeof(struct RevokeInfo));
            STOP_IT_IF_ERROR(NULL == pst_revoke_info[i], RevokeInfo_t, "calloc failed\n");
        }
        FILL_WITH_OCTET_STRING(pst_revoke_info[i]->id, revoke_info_id_s, 10, _ret);
        STOP_IT_IF_ERROR(0 != _ret, OCTET_STRING_t, "OCTET_STRING_fromBuf failed\n");
        pst_revoke_info[i]->hashAlg = HashAlgorithm_sha256;
        _ret = asn_set_add(&pst_to_be_signed_crl->entries.list, pst_revoke_info[i]);
        STOP_IT_IF_ERROR(0 != _ret, RevokeInfo_t, "asn_set_add failed\n");
    }
    
    fp = fopen(argv[1], "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    // 编码
    ec = oer_encode(&asn_DEF_ToBeSignedCrl, pst_to_be_signed_crl, write_callback, (void*)fp);
    STOP_IT_IF_ERROR(1 == ec.encoded, oer_encode, "%d ecode(%d): %s\n", 
                                            __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    xer_fprint(stdout, &asn_DEF_ToBeSignedCrl, pst_to_be_signed_crl);
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
            if (0 == (++j % 10)) fprintf(stdout, "\n");
        }       
    }
    printf("\n");
    // 解码
    if (fp) fclose(fp);
    memset(buf, 0, sizeof(buf));
    
    fp = fopen(argv[1], "rb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));

    fseek(fp, 0, SEEK_END);
    bsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    rsize = fread(buf, 1, sizeof(buf), fp);
    STOP_IT_IF_ERROR(rsize <= 0, fread, strerror(errno));
    
    STOP_IT_IF_ERROR(bsize != rsize, "", "binary file size error(%ld != %ld)\n", bsize, rsize);
    
    rval = oer_decode(0, &asn_DEF_ToBeSignedCrl, (void**)&pst_to_be_signed_crl_de, buf, bsize);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            "%s: Broken Type encoding at byte %ld\n", argv[1], (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_ToBeSignedCrl, pst_to_be_signed_crl_de);
    // 解析 SEQUENCE OF, 再造 ToBeSignedCrl
    fprintf(stdout, "======================= 堆中进行 =======================\n" );
    if (fp) fclose(fp);
    fp = fopen(argv[1], "wb");
    STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    pst_ToBeSignedCrl = calloc(1, sizeof(struct ToBeSignedCrl));
    STOP_IT_IF_ERROR(NULL == pst_ToBeSignedCrl, ToBeSignedCrl_t, "calloc failed\n");
    pst_ToBeSignedCrl->crlSerial = pst_to_be_signed_crl_de->crlSerial;
    pst_ToBeSignedCrl->issueDate = pst_to_be_signed_crl_de->issueDate;
    pst_ToBeSignedCrl->nextCrl = pst_to_be_signed_crl_de->nextCrl;
    for (i = 0; i < pst_to_be_signed_crl_de->entries.list.count; i++) {
        struct RevokeInfo* pst_RevokeInfo = NULL;
        pst_RevokeInfo = calloc(1, sizeof(struct RevokeInfo));
        STOP_IT_IF_ERROR(NULL == pst_RevokeInfo, RevokeInfo_t, "calloc failed\n");
        pst_RevokeInfo->hashAlg = pst_to_be_signed_crl_de->entries.list.array[i]->hashAlg;
        FILL_WITH_OCTET_STRING(pst_RevokeInfo->id, pst_to_be_signed_crl_de->entries.list.array[i]->id.buf,
                               pst_to_be_signed_crl_de->entries.list.array[i]->id.size, _ret);      
        _ret = asn_set_add(&pst_ToBeSignedCrl->entries.list, pst_RevokeInfo);
        STOP_IT_IF_ERROR(0 != _ret, RevokeInfo_t, "asn_set_add failed\n");
    }
    // 编码
    ec = oer_encode(&asn_DEF_ToBeSignedCrl, pst_ToBeSignedCrl, write_callback, (void*)fp);
    STOP_IT_IF_ERROR(1 == ec.encoded, oer_encode, "%d ecode(%d): %s\n", 
                                            __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
    
    xer_fprint(stdout, &asn_DEF_ToBeSignedCrl, pst_ToBeSignedCrl);
    fprintf(stdout, "\n");
    // 解析 SEQUENCE OF, 再造 ToBeSignedCrl （不应该在栈中进行）
    // fprintf(stdout, "======================= 栈中进行 =======================\n" );
    // if (fp) fclose(fp);
    // fp = fopen(argv[1], "wb");
    // STOP_IT_IF_ERROR(NULL == fp, fopen, strerror(errno));
    
    // to_be_signed_crl.crlSerial = pst_to_be_signed_crl_de->crlSerial;
    // to_be_signed_crl.issueDate = pst_to_be_signed_crl_de->issueDate;
    // to_be_signed_crl.nextCrl = pst_to_be_signed_crl_de->nextCrl;
    // for (i = 0; i < pst_to_be_signed_crl_de->entries.list.count; i++) {
        // struct RevokeInfo revoke_info;
        // revoke_info.hashAlg = pst_to_be_signed_crl_de->entries.list.array[i]->hashAlg;
        // FILL_WITH_OCTET_STRING(revoke_info.id, pst_to_be_signed_crl_de->entries.list.array[i]->id.buf,
                               // pst_to_be_signed_crl_de->entries.list.array[i]->id.size, _ret);       
        // _ret = asn_set_add(&to_be_signed_crl.entries.list, &revoke_info);
        // STOP_IT_IF_ERROR(0 != _ret, RevokeInfo_t, "asn_set_add failed\n");
    // }
        
    RET = 0;
cleanup:
    if (0 == RET) fprintf(stdout, "=== encode success ===\n");
    else fprintf(stdout, "failed\n");
    
    if (fp) fclose(fp);
    
    ASN_STRUCT_FREE(asn_DEF_ToBeSignedCrl, pst_to_be_signed_crl);
    ASN_STRUCT_FREE(asn_DEF_ToBeSignedCrl, pst_to_be_signed_crl_de);
    ASN_STRUCT_FREE(asn_DEF_ToBeSignedCrl, pst_ToBeSignedCrl);
    
    if (0 == RET) fprintf(stdout, "==== free success ====\n");
    else fprintf(stdout, "failed\n");
    
    return RET;
}
