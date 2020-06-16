#include <stdio.h>
#include <sys/types.h>
#include <Rectangle.h>
#include <errno.h>

/** 功能: 固定结构 Rectangle 解码，了解一下流程。 */

#define USAGE         \
    "Usage: ./cmd <in file>\n"

int main(int argc, char *argv[])
{
    char buf[1024];
    asn_dec_rval_t rval;
    Rectangle_t *rectangle = 0;
    FILE *fp;
    size_t size;
    int ret = -1;

    if (argc < 2) {
        printf(USAGE);
        return -1;
    }
    if ((fp = fopen(argv[1], "rb")) == NULL) {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
        goto cleanup;
    }
    if ((size = fread(buf, 1, sizeof(buf), fp)) <= 0) {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
        goto cleanup;
    }
    // oer 解码
    rval = oer_decode(0, &asn_DEF_Rectangle, (void**)&rectangle, buf, size);
    if (rval.code != RC_OK) {
        fprintf(stderr, "%s: Broken Rectangle encoding at byte %ld\n", argv[1], (long)rval.consumed);
        goto cleanup;
    }
    // xml 格式打印
    xer_fprint(stdout, &asn_DEF_Rectangle, rectangle);
    
    ret = 0;
cleanup:
    if (ret == 0) fprintf(stdout, "===== executed success =====\n");
    if (fp) fclose(fp);
    ASN_STRUCT_FREE(asn_DEF_Rectangle, rectangle);

    return 0;
}