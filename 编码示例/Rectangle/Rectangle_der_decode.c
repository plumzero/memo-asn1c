#include <stdio.h>
#include <sys/types.h>
#include <Rectangle.h>
#include <errno.h>

/**
    功能：
        将der格式文件解码，并使用C结构存储数据   
 */
int main(int argc, char *argv[])
{
    char buf[1024];
    asn_dec_rval_t rval;
    Rectangle_t *rectangle = 0;
    FILE *fp;
    size_t size;
    //参数校验
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <ber or der input filename>\n", argv[0]);
        return -1;
    }
    if ((fp = fopen(argv[1], "rb")) == NULL)
    {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
        goto cleanup;
    }
    if ((size = fread(buf, 1, sizeof(buf), fp)) <= 0)
    {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
        goto cleanup;
    }
    //将BER或DER格式文件解码，C结构存储
    rval = ber_decode(0, &asn_DEF_Rectangle, (void**)&rectangle, buf, size);
    if (rval.code != RC_OK)
    {
        fprintf(stderr, "%s: Broken Rectangle encoding at byte %ld\n", argv[1], (long)rval.consumed);
        exit(1);
    }
    //XML格式打印
    xer_fprint(stdout, &asn_DEF_Rectangle, rectangle);
    fprintf(stdout, "\n");
    //ASN.1格式打印
    asn_fprint(stdout, &asn_DEF_Rectangle, rectangle);
    
cleanup:
    if (fp) fclose(fp);
    ASN_STRUCT_FREE(asn_DEF_Rectangle, rectangle);

    return 0;
}