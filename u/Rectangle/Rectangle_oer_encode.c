#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <Rectangle.h>

static int write_callback(const void *buffer, size_t size, void *app_key)
{
    FILE *fp = app_key;
    size_t wrote = fwrite(buffer, 1, size, fp);
    return (wrote == size) ? 0 : -1;
}

/** 功能: 固定结构 Rectangle 编码，了解一下流程。 */

#define USAGE         \
    "Usage: ./cmd <out file>\n"

int main(int argc, char *argv[])
{
    int ret = -1;
    Rectangle_t *rectangle;
    asn_enc_rval_t rval;
    FILE *fp;
    char errbuf[1024];
    size_t errlen;

    if (argc < 2) {
        printf(USAGE);
        return -1;
    }
    if ((fp = fopen(argv[1], "wb")) == NULL) {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
        goto cleanup;   
    }
    // 创建对象
    if ((rectangle = calloc(1, sizeof(Rectangle_t))) == NULL) {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
        goto cleanup;
    }
    // 赋值
    rectangle->height = 125;
    rectangle->width = 23;
    // 约束性验证
    errlen = sizeof(errbuf);
    if ((ret = asn_check_constraints(&asn_DEF_Rectangle, rectangle, errbuf, &errlen)) != 0) {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
        goto cleanup;
    }
    // oer 编码
    rval = oer_encode(&asn_DEF_Rectangle, rectangle, write_callback, (void *)fp);
    if (rval.encoded == -1) {
        fprintf(stderr, "%d ecode(%lu): %s\n", __LINE__, rval.encoded, rval.failed_type ? rval.failed_type->name : "unknown");
        goto cleanup;
    }
    // xml 格式打印
    xer_fprint(stdout, &asn_DEF_Rectangle, rectangle);

    ret = 0;
cleanup:
    if (ret == 0) fprintf(stdout, "===== executed success =====\n");
    if (fp) fclose(fp);
    ASN_STRUCT_FREE(asn_DEF_Rectangle, rectangle);

    return ret;
}