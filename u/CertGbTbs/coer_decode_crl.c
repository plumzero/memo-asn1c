#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stddef.h>
#include "Crl.h"

#define VERSION                 2

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

int main(int argc, char *argv[]) 
{
    int RET = -1, _ret;
    FILE *fp = NULL;
    unsigned char binbuf[1024] = { 0 };
    size_t bsize = 0, rsize = 0;
    asn_dec_rval_t rval;
    size_t i, j, k;
    
    FILE *fin = NULL;
    
    struct Crl* pst_crl = NULL;
    
    if (argc < 2) {
        printf("./exe <output coer file>\n");
        return -1;
    }

    fin = fopen(argv[1], "rb");
    STOP_IT_IF_ERROR(NULL == fin, fopen, strerror(errno));

    fseek(fin, 0, SEEK_END);
    bsize = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    
    rsize = fread(binbuf, 1, sizeof(binbuf), fin);
    STOP_IT_IF_ERROR(rsize <= 0, fread, strerror(errno));
    
    STOP_IT_IF_ERROR(bsize != rsize, "", "binary file size error(%ld != %ld)\n", bsize, rsize);
    
    // 解码
    rval = oer_decode(0, &asn_DEF_Crl, (void**)&pst_crl, binbuf, bsize);
    STOP_IT_IF_ERROR(rval.code != RC_OK, oer_decode, 
                            "%s: Broken Type encoding at byte %ld\n", argv[1], (long)rval.consumed);
    
    xer_fprint(stdout, &asn_DEF_Crl, pst_crl);
    fprintf(stdout, "\n");
    
    RET = 0;
cleanup:
    if (0 == RET) fprintf(stdout, "=== decode success ===\n");
    else fprintf(stdout, "failed\n");
    
    if (fin) fclose(fin);
    
    ASN_STRUCT_FREE(asn_DEF_Crl, pst_crl);
    
    if (0 == RET) fprintf(stdout, "==== free success ====\n");
    else fprintf(stdout, "failed\n");
    
    return RET;
}
