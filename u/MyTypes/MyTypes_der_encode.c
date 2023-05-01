#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include "MyTypes.h"

static int write_callback(const void *buffer, size_t size, void *app_key)
{
    FILE *fp = app_key;
    size_t wrote = fwrite(buffer, 1, size, fp);
    return (wrote == size) ? 0 : -1;
}

/**
    功能：
        1.将ASN.1编码为der格式;
        2.对ASN.1的 OBJECT IDENTIFIER, SEQUENCE OF, BIT STRING类型进行编码测试
    ASN.1结构：
        MyTypes ::= SEQUENCE 
        {
            myObjectId      OBJECT IDENTIFIER,              -- 对象标识符
            mySeqOf         SEQUENCE OF MyInt,              -- MyInt list
            myBitString     BIT STRING{
                                muxToken(0),
                                modemToken(1) }
        }
        MyInt ::= INTEGER(0..65535)
    对应的C结构类型：
        typedef struct MyTypes{
            OBJECT_IDENTIFIER_t myObjectId;
            struct mySeqOf {
                A_SEQUENCE_OF(MyInt_t) list;
            }mySeqOf;
            BIT_STRING_t myBitString;
        }MyTypes_t;
    注意：
        1.OBJECT_IDENTIFIER_t的定义是 INTEGER_t 类型，它是一个足够长度的整数
        2.SEQUENCE OF 的元素必须在堆中分配并添加
        3.可能 asn1c 采用了 __attribute__ 的原因（不是太懂），所以对于myInt分配的动态内存，使用了 
          offsetof 宏进行释放
    测试：
        内存泄漏测试
            valgrind --tool=memcheck --leak-check=full ./asn2der out.der
        生成文件测试
            openssl asn1parse -inform der -in out.der -i
 */
int main(int argc, char *argv[])
{
    int ret = -1;
    MyTypes_t *myType;
    MyInt_t *myInt;
    asn_enc_rval_t ec;
    FILE *fp;
    char errbuf[1024];
    size_t errlen, i;
    int oid[] = { 1, 3, 6, 1, 4, 1, 9363, 1, 5, 0 };
    int seqs[] = {111, 222, 333, 444, 555, 666, 777, 888, 999};
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
    if ((myType = calloc(1, sizeof *myType)) == NULL)
    {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
        goto cleanup;
    }
    //填充OBJECT IDENTIFIER类型
    if ((ret= OBJECT_IDENTIFIER_set_arcs(&myType->myObjectId, oid, sizeof(*oid), sizeof(oid) / sizeof(*oid))) != 0)
        goto cleanup;
    //填充SEQUENCE OF类型
    for (i = 0; i < sizeof(seqs) / sizeof(*seqs); i++)
    {
        myInt = calloc(1, sizeof *myInt);
        assert(myInt);
        *myInt = seqs[i];
        if ((ret= ASN_SEQUENCE_ADD(&myType->mySeqOf, myInt)) != 0)
        {
            fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
            goto cleanup;
        }
    }
    //填充BIT STRING类型
    if ((myType->myBitString.buf = calloc(1, 1)) == NULL)   //一个字节
    {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, errno, strerror(errno));
        goto cleanup;
    }
    myType->myBitString.size = 1;
    myType->myBitString.buf[0] |= 1 << (7 - myBitString_muxToken);
    myType->myBitString.buf[0] |= 1 << (7 - myBitString_modemToken);
    //八位组中未使用的比特数，如 192 八位二进制形式为 11000000 有6位未使用
    myType->myBitString.bits_unused = 6;
    //开始正式编码
    ec = der_encode(&asn_DEF_MyTypes, myType, write_callback, (void *)fp);
    if (ec.encoded == -1)
    {
        fprintf(stderr, "%d ecode(%d): %s\n", __LINE__, ec.failed_type ? ec.failed_type->name : "unknown");
        goto cleanup;
    }
    //XML格式打印
    xer_fprint(stdout, &asn_DEF_MyTypes, myType);
    printf("\n");
    //ASN.1格式打印
    asn_fprint(stdout, &asn_DEF_MyTypes, myType);
    ret = 0;
cleanup:
    fprintf(stderr, "ret (%8X)\n", ret);
    if (fp) fclose(fp);
    ASN_STRUCT_FREE(asn_DEF_MyTypes, myType);
    
    return ret;
}