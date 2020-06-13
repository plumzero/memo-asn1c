
## 编译问题
- 编译时报错:
  ```shell
    /tmp/ccdvIGpR.o:(.data.rel+0x38): undefined reference to `BIT_STRING_decode_oer'
    /tmp/ccdvIGpR.o:(.data.rel+0x40): undefined reference to `BIT_STRING_encode_oer'
  ```
  可能是 asn1c 处理 .asn 文件时没有生成 BIT_STRING_oer.c 文件，从其他目录将其拷贝过来即可
  
## 编码问题
- 能够编译通过，但运行时报段错误，可能的原因是:
    + 没有为一些结构体在堆中分配内存；
    + 分配堆内存的方式不对，比如是连续分配还是小块分配；
- 能够编译通过，但运行进行 xml 打印时没有全部打印，如下:
  ```shell
    # ./mycoer         
    <SignedCertificateRequest>
        <hashId><sm3/></hashId>
        <tbsRequest>
            <version>0</version>
            <content>
                <eca-ee>
                    <eeEcaCertRequest>
                        <version>1</version>
                        <currentTime>1582200693</currentTime>
                        <tbsData>
                            <id>
  ```
  原因可能是一些结构体没有 OPTIONAL 标识，即应该将其编码出来，但实际上并未对其进行编码。
- 关于 OCTET_STRING_t 的 OCTET_STRING_fromBuf 的调用方法，如果直接使用会引发随机崩溃，暂时还
  不清楚怎么回事，应该这样使用:
  ```c
    #define FILL_WITH_OCTET_STRING(Ivalue, Ibuf, Isize, oRet)       \
        do {                                                        \
            OCTET_STRING_t ostr;                                    \
            memset(&ostr, 0, sizeof(OCTET_STRING_t));               \
            oRet = OCTET_STRING_fromBuf(&ostr, Ibuf, Isize);        \
            Ivalue = ostr;                                          \
        } while (0)
  ```
- Opaque_t 在有些场合下应该理解为不透明指针
  ```c
    typedef struct Ieee1609Dot2Content {
        Ieee1609Dot2Content_PR present;
        union Ieee1609Dot2Content_u {
            Opaque_t     unsecuredData;
            struct SignedData   *signedData;
            EncryptedData_t  encryptedData;
            Opaque_t     signedCertificateRequest;
            /*
             * This type is extensible,
             * possible extensions are below.
             */
        } choice;
        
        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
    } Ieee1609Dot2Content_t;
  ```
    + 如上，union 类型结构体 Ieee1609Dot2Content 中名字为 signedCertificateRequest 的成员其类
      型为 Opaque_t，是一个 OCTET_STRING_t，即一个字符串。
    + 但实际上它在此处是一个结构体的二进制序列化表示，应该将其看作一个类似于 C 语言中的不透明
      指针，这时应该将其在堆中分配内存。
    + 如果在编码时将 signedCertificateRequest 成员在栈中分配内存，则最后释放时会因为结构体被
      擦除(变为字符串)而产生内存泄漏。
    + 正确的方法是将该成员以结构体的形式在堆中分配内存，然后单独对该成员进行编码，将编码输出的
      缓冲内容填充到 signedCertificateRequest(类型为 Opaque_t)中，最后显式调用 ASN_STRUCT_FREE
      释放该结构体。
- asn_set_add 常见问题
    + 常见问题为段错误，造成这种问题的原因很可能是上下文数组索引窜用。
- 截止目前(2020.05.04)，asn1c 对 `DEFAULT` 字段的支持不是太好，对于下面的 asn1 结构:
  ```shell
    PsidGroupPermissions ::= SEQUENCE  {
        subjectPermissions SubjectPermissions,
        minChainLength     INTEGER DEFAULT 1,
        chainLengthRange   INTEGER DEFAULT 0, 
        eeType             EndEntityType DEFAULT {app}
    }
  ```
  asn1c 会解析成如下结构:
  ```c
    typedef struct PsidGroupPermissions {
        SubjectPermissions_t     subjectPermissions;
        long    *minChainLength /* DEFAULT 1 */;
        long     chainLengthRange       /* DEFAULT 0 */;
        EndEntityType_t *eeType /* DEFAULT {app} */;

        /* Context for parsing across buffer boundaries */
        asn_struct_ctx_t _asn_ctx;
   } PsidGroupPermissions_t;
  ```
  这显然是不正确的，要做相应的修改。事实上，可以将 DEFAULT 理解为 OPTIONAL + PRESENT, 这样可以将
  asn1 结构体定义进行如下修改:
  ```shell
    PsidGroupPermissions ::= SEQUENCE  {
        subjectPermissions SubjectPermissions,
        minChainLength     INTEGER OPTIONAL,
        chainLengthRange   INTEGER OPTIONAL, 
        eeType             EndEntityType OPTIONAL
    }
    (WITH COMPONENTS { ..., minChainLength PRESENT} |
     WITH COMPONENTS { ..., chainLengthRange PRESENT} |
     WITH COMPONENTS { ..., eeType PRESENT})
  ```
  之后再生成源文件，编解码即可。
      
## 运行调试问题
- 调用编码函数失败，这里以 oer 编码为例
    + 编译没问题，运行时编码、解码也没问题，但在调用 oer_encode 函数时编码失败；
    + 一般造成这种错误的原因是某个成员在编码时没有遵守 asn1 约束，如果根据 .asn 文件对照代码
      的话，量大时肯定很麻烦，这个时候可以通过 gdb 工具调试快速定位错误；
    + 调试内容源代码主要位于 constr_SEQUENCE_oer.c 的 SEQUENCE_encode_oer 函数中，具体需要关注
      的代码如下:
      ```c
        for(edx = 0; edx < td->elements_count; edx++) {
            
            // ...
            
            if(er.encoded == -1) {
                ASN_DEBUG("... while encoding %s member \"%s\"\n", td->name,
                          elm->name);
                return er;
            }
            computed_size += er.encoded;
        }
      ```
      调试时如果在编码某个成员结构 er.encoded 值返回为 -1, 则错误就出现在这个成员结构上。
- 内存释放大溃败
    + 编译没问题，运行时编码、解码也没问题，但在调用  ASN_STRUCT_FREE 等释放函数时出现段错误；
    + 一般此类问题基本上都能通过 gdb 工具调试发现，不过在调试时需要进入开源源文件中，而其中最
      常出错的文件及函数是 constr_SEQUENCE.c 中的 SEQUENCE_free 函数。
    + 通过 gdb 工具进入上述文件中调试，要一步步地，细致地时刻关注堆栈情况，找到问题所在。
- 指针分配内存异常，gdb 也派不上用场
    + 在为结构体或其成员分配堆内存时，一定不要失误，否则就可能会出现当前所述问题；
    + 问题描述: 编码正常，运行编码正常，但释放时报段错误；
    + 原以为是类似内存释放大溃败的问题，结果调试很长时间也没找到到底是给哪个地方分配错了内存，
      调试发现在 constr_SEQUENCE.c : SEQUENCE_free 中如下语句:
      ```c
        ctx = (asn_struct_ctx_t *)((char *)sptr + specs->ctx_offset);
        FREEMEM(ctx->ptr);
      ```
      走到 FREEMEM 时出错，ctx->ptr 此时不空 0x0，正常情况下是为 0x0 的；
    + 最后发现原来是 calloc 对象错误，如下:
      ```c
        pstSignedEeEnrollmentCertResponse = calloc(1, sizeof(pstSignedEeEnrollmentCertResponse));
      ```
      正确的应该是:
      ```c
        pstSignedEeEnrollmentCertResponse = calloc(1, sizeof(SignedEeEnrollmentCertResponse_t));
      ```
      发现这个错误不是 gdb 的功劳，而是通过和其他结构体对比发现个数不一致，才发觉的。
    + 遇到这种问题，gdb 也没办法了，记录一下以作警示。
- 对解码的调试
    + 虽然至今为止还没有发生过解码失败的问题，但还是有必要记录一下对解码的 gdb 调试过程；
    + 调试内容源代码主要位于 constr_SEQUENCE_oer.c 的 SEQUENCE_decode_oer 函数中，通常需要关注的
      代码段有三部分:
      ```c
        /** [1] 对父结构解码 */
        for(edx = (ctx->step >> 1); IN_ROOT_GROUP_PRED(edx);
            edx++, ctx->step = (ctx->step & ~1) + 2) {
            asn_TYPE_member_t *elm = &td->elements[edx];

            ASN_DEBUG("Decoding %s->%s", td->name, elm->name);

            assert(!IN_EXTENSION_GROUP(specs, edx));
      ```
      上面的代码中, td 记录的是解码的结构体信息(主要关注 td->name 字段)，elm 记录的是结构体成员(
      也是关注 elm->name 字段)。
      ```c
        /** [2] 对结构中的成员进行迭代解码 */
        rval = elm->type->op->oer_decoder(
            opt_codec_ctx, elm->type,
            elm->encoding_constraints.oer_constraints, memb_ptr2, ptr,
            size);
      ```
      因为结构体成员 elm 可能也是一个结构体，所以进行了迭代式解码，这个时候 elm 就变成了新的 td 。
      ```c
        /** [3] 记录每个结构中成员的解码结果 */
        switch(rval.code) {
        case RC_OK:
            ADVANCE(rval.consumed);
            break;
        case RC_WMORE:
            ASN_DEBUG("More bytes needed at element %s \"%s\"", td->name,
                      elm->name);
            ADVANCE(rval.consumed);
            RETURN(RC_WMORE);
        case RC_FAIL:
            ASN_DEBUG("Decoding failed at element %s \"%s\"", td->name,
                      elm->name);
            RETURN(RC_FAIL);
        }
      ```
      记录对每个结构体中每个成员的解码结果。哪个成员解码出错，可以通过上面的返回进行判断。
