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

/**
  *  测试：
  *      内存泄漏测试
  *          valgrind --tool=memcheck --leak-check=full ./exe out.der
  *      生成文件测试
  *          openssl asn1parse -inform der -in out.der -i
  */ 
int main(int argc, char *argv[])
{
    int ret = -1;
    Rectangle_t *rectangle;
    asn_enc_rval_t ec;
    FILE *fp;
    char errbuf[1024];
    size_t errlen;
    //参数校验
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <der output filename>\n", argv[0]);
        return -1;
    }
    if ((fp = fopen(argv[1], "wb")) == NULL)
    {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
        goto cleanup;   
    }
#line 1
    // Rectangle_t rect;
    // rectangle = &rect;
    //分配内存
#line 2
    if ((rectangle = calloc(1, sizeof(Rectangle_t))) == NULL)
    {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
        goto cleanup;
    }
#line 3
    //赋值
    rectangle->height = 125;
    rectangle->width = 23;
    //约束性验证
    errlen = sizeof(errbuf);
    if ((ret = asn_check_constraints(&asn_DEF_Rectangle, rectangle, errbuf, &errlen)) != 0)
    {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
        goto cleanup;
    }
    //DER编码
    ec = der_encode(&asn_DEF_Rectangle, rectangle, write_callback, (void *)fp);
    if (ec.encoded == -1)
    {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
        goto cleanup;
    }
    //XML格式打印
    xer_fprint(stdout, &asn_DEF_Rectangle, rectangle);
    fprintf(stdout, "\n");
    //ASN.1格式打印
    asn_fprint(stdout, &asn_DEF_Rectangle, rectangle);
    ret = 0;
cleanup:
    fprintf(stderr, "ret (%8X)\n", ret);
    if (fp) fclose(fp);
    //如果将 #line 1 和 #line 2 之间关闭，将 #line 2 和 #line 3 之间打开，使用下面的函数释放
    ASN_STRUCT_FREE(asn_DEF_Rectangle, rectangle);
    //如果将 #line 1 和 #line 2 之间打开，将 #line 2 和 #line 3 之间关闭，使用下面的函数释放
    // ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Rectangle, rectangle);
    
    return ret;
}