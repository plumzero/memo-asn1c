#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include "MyTypes.h"

/**
    功能：
        将der格式文件解码，并使用C结构存储数据
        
        解析失败！！！
 */
int main(int argc, char *argv[])
{
    int i, ret = -1;
    char buf[1024];
    asn_dec_rval_t rval;
    MyTypes_t *myType = 0;
    MyInt_t *myInt = 0;
    
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
    rval = ber_decode(0, &asn_DEF_MyTypes, (void**)&myType, buf, size);
    if (rval.code != RC_OK)
    {
        fprintf(stderr, "%s: Broken MyType encoding at byte %ld\n", argv[1], (long)rval.consumed);
        goto cleanup;
    }
    //XML格式打印
    xer_fprint(stdout, &asn_DEF_MyTypes, myType);
    fprintf(stdout, "\n");
    //ASN.1格式打印
    asn_fprint(stdout, &asn_DEF_MyTypes, myType);
    //解码就是将数据取出的过程，下面进行取出数据的操作，其实就是编码的逆运算
    //取出 OBJECT IDENTIFIER 类型数据，数组存储
    unsigned long fixed_arcs[10];
    unsigned long *arcs = fixed_arcs;
    int arc_type_size = sizeof(fixed_arcs[0]);
    int arc_slots = sizeof(fixed_arcs)/sizeof(fixed_arcs[0]);
    int count;
    if ((ret = OBJECT_IDENTIFIER_get_arcs(&myType->myObjectId, arcs, arc_type_size, arc_slots)) == -1)
        goto cleanup;
    count = ret;
    if (count > arc_slots)
    {
        arc_slots = count;
        arcs = realloc(arcs, arc_type_size * arc_slots);
        assert(arcs != NULL);
        count = OBJECT_IDENTIFIER_get_arcs(&myType->myObjectId, arcs, arc_type_size, arc_slots);
        assert(count == arc_slots);
    }
    for (i = 0; i < count; i++)
        printf(" %d", arcs[i]);
    printf("\n");
    //取出 SEQUENCE OF 类型，数组存储
    unsigned long iarray[10];
    unsigned long *iarcs = iarray;
    int iarc_type_size = sizeof(iarray[0]);
    int iarc_slots = sizeof(iarray) / sizeof(*iarray);
    rval = SEQUENCE_decode_ber(0, &myType->mySeqOf, (void**)&myInt, buf, size, 0);
    if (rval.code != RC_OK)
    {
        fprintf(stderr, "%s: Broken MyType encoding at byte %ld\n", argv[1], (long)rval.consumed);
        goto cleanup;
    }
    if (rval.consumed > iarc_slots * iarc_type_size)
    {
        ASN_STRUCT_FREE(asn_DEF_MyInt, myInt);
        iarc_slots = rval.consumed / iarc_type_size;
        iarcs = realloc(iarcs, iarc_type_size * iarc_slots);
        assert(iarcs != NULL);
        rval = SEQUENCE_decode_ber(0, &myType->mySeqOf, (void**)&myInt, buf, size, 0);
        assert(rval.consumed == iarc_slots * iarc_type_size);
    }
    for (i = 0; i < rval.consumed; i++)
        printf(" %d", iarcs[i]);
    printf("\n");
    
    ret = 0;
cleanup:
    fprintf(stderr, "ret (%8X)\n", ret);
    if (fp) fclose(fp);
    if (arcs != fixed_arcs) free(arcs);
    ASN_STRUCT_FREE(asn_DEF_MyTypes, myType);

    return 0;
}