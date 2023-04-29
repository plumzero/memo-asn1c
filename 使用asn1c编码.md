
快速入门，编码注意，常用结构。

## asn1c 编码快速入门
- 对 ASN1 进行编码和解码的过程也称为序列化和反序列化；
- 通过 asn1c 实现对 ASN1 结构的编解码之前，要构建供 C/C++ 运行的环境，通过 asn1c 可以生成
  一组 .h, .c 文件来完成环境的搭建；
- 对每一个 ASN1 结构，asn1c 都会为其单独生成一个 .h 文件和 .c 文件；
- asn1c 函数内部实现复杂，即使对 ASN.1 编码有所了解，想要迅速阅读函数内部实现可能也
  会较困难，此时应该将函数内部的实现完全信任于开源方，自己则从结构体变量入手，并对
  传入参数进行追踪，了解函数使用方法即可。即，对 asn1c 的学习要只看结果，不看过程；
- asn1c 函数众多，主要是因为 ASN.1 类型众多，且每种类型处理方式不同，但开源方已经为
  我们实现了对底层函数实现的封装，一般在学习时只需要了解下列几种类型函数即可:
    **合法校验 编码 解码 释放 打印**
- CER 和 DER 编码是 BER 编码的子集，所以可以使用 BER 的解码器对前面两种进行解码；

## asn1c 不是万能的，使用 asn1c 编码应注意
- 对某个结构体进行编码，必须完成对该结构体内部所有成员的编码，才能输出到文件，否则
  会跳过写回调，无法实现输出；
- 对于 OPTIONAL 选项成员，在生成的相应 c 结构体中，会将其定义为指针成员，否则会定义
  成非指针成员。对指针成员应在堆中分配内存，非指针成员应在栈中分配内存，必须严格遵
  守，否则在释放时极易引发段错误；
- asn1c 暂时不支持对 choice 类型的 ABSENT 限制，如下:
  ```shell
    Hour ::= CHOICE  {
        microseconds     Uint16,
        milliseconds     Uint16,
        seconds          Uint16,
        minutes          Uint16,
        hours            Uint16,
        sixtyHours       Uint16,
        years            Uint16
    }

    MyHour ::= SEQUENCE {
        version         Uint8(1),
        whichChoice     Hour(WITH COMPONENTS {
            years  ABSENT }
        )
    }
  ```
  通过 asn1c 可以完成对 MyHour 的编码，但编码后的文件在[测试平台](https://asn1.io/asn1playground/)
  上无法通过约束校验测试。 
- 虽然说 UTF8String_t 是 OCTET_STRING_t 的别名:
  ```c
    typedef OCTET_STRING_t UTF8String_t;
  ```
  但对 UTF8String_t 使用 OCTET_STRING_fromBuf 报段错误。应该把 UTF8String_t 当作一
  种不同于 OCTET_STRING_t 的字符串来处理。(需要进一步验证)
- 对于 SEQUENCE_OF ，不能像下面这样一次性分配内存：
  ```c
    calloc(1, sizeof(struct SinglePart) * SEQUENCE_OF_SIZE);
  ```
  而应该这样一点点分配内存：
  ```c
    calloc(1, sizeof(struct SinglePart));
    calloc(1, sizeof(struct SinglePart));
    ...
    calloc(1, sizeof(struct SinglePart));
  ```      
  一共分配 SEQUENCE_OF_SIZE 次。
  必须严格遵守，否则会报段错误。
- 内存释放注意
  asn1c 提供了三种释放函数，如下:
  ```c
    ASN_STRUCT_FREE
    ASN_STRUCT_FREE_CONTENTS_ONLY
    ASN_STRUCT_RESET
  ```
  以 struct Certificate 进行示例，其使用场景如下:
    + 在栈中分配内存时:
      ```c
        struct Certificate cert;
        // do sth ...
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, cert);
      ```
    + 在堆中分配内存时:
      ```c
        struct Certificate* pcert = NULL;
        // do sth ...
        ASN_STRUCT_FREE(asn_DEF_Certificate, pcert); 
      ```
      上面的写法是较为常用的写法，其等价于下面的写法:
      ```c
        struct Certificate* pcert = NULL;
        // do sth ...
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_Certificate, pcert);
        if (pcert) free(pcert);
      ```
      这种写法不推荐。
  ASN_STRUCT_RESET 的使用和 ASN_STRUCT_FREE_CONTENTS_ONLY 相同，罕用。

### 约束校验
- 编码完成后，编译、运行都没问题，这还不够，还要进行最后的约束校验，以验证编码是否满足原 .asn 文
  件要求。
- asn1c 提供了自己的校验函数，但实际使用时并不会采用，而是在网站
    [ASN1 语法在线测试](https://asn1.io/asn1playground/)
  上进行校验，这样更便捷一些。

## asn1 编码应该进行哪些测试
- 内存泄漏测试
    + 通过 valgrind 工具实现。
    + `valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./myprogram`
- 约束校验测试
    + 通过 [ASN1 语法在线测试](https://asn1.io/asn1playground/)实现；
    + 目的是校验编码结果是否符合 .asn 文件的约束要求。
- 健壮性测试
    + 应该对编码或解码程序进行反复多次测试，以保证其健壮性。

## 最后，有必要了解一些常用结构体与函数
### 几个重要的结构体
- asn_enc_rval_t
    + 功能: 编码函数（如 der_encode, xer_encode ）的返回值
    + 成员及含义:
      ```c
        ssize_t encoded;
            成功  记录已编码的字节数
            失败  -1
        struct asn_TYPE_descriptor_s *failed_type;
            encoded为-1时可以使用，记录无法编码的结构变量
        void *structure_ptr;
            指向编码的结构变量
      ```
    + 头文件定义: asn_codecs.h
+ asn_dec_rval_t
    + 功能: 解码函数（如 ber_decode, xer_decode ）的返回值
    + 成员及含义:
      ```c
        enum ash_dec_rval_code_e code;
            返回枚举，共有三种取值，其名称和含义如下：
                RC_OK       解码成功
                RC_WRONG    待解码数据不足，需再次调用解码函数加载数据缓冲
                RC_FAIL     解码失败
        size_t consumed;
                已经解码的数据长度
      ```
    + 头文件定义: asn_codecs.h
    
## 几种重要的通用函数
为了便于理解，可以将目标语言结构看作C语言结构；
只对 BER, DER, XER 编解码操作进行说明，不对 PER 编解码操作进行说明；
- 合法校验函数
  ```c
    int asn_check_constraints(struct asn_TYPE_descriptor_t *type_descriptor,
        const void *struct_ptr,
        char *errbuf,
        size_t *errlen);
  ```
    + 功能: 对ASN.1类型和与其对应的目标语言结构进行合法校验
    + 参数：
      ```c
        type_descriptor     in          ASN.1类型标识结构
        struct_ptr          in          目标语言结构
        errbuf              in | out    存放错误描述的缓冲
        errlen              in | out    输入是缓冲的长度，输出是错误描述的长度
      ```
    + 返回：
        成功  0
        失败 -1
    + 说明：
        对目标语言结构进行编码前，可以通过 asn_TYPE_descriptor_t.check_constraints 
        来实现合法校验。但对 check_constraints 的调用地址会因目标语言结构类型不同而
        异， asn_check_constraints 函数通过对底层进行封装解决了这种困扰。
    + 头文件及实现文件: constraints.h constraints.c
- 编码函数
  ```c  
  asn_enc_rval_t der_encode(struct asn_TYPE_descriptor_s *type_descriptor,
        void *struct_ptr,
        asn_app_consume_bytes_f *consume_bytes_cb,
        void *app_key
    );
  ```
    + 功能: 对ASN.1类型对应的目标语言结构进行DER编码， ber_decode 是其对应的解码函数
    + 参数:
      ```c
        type_descriptor     in          ASN.1类型标识结构
        struct_ptr          in          目标语言结构
        consume_bytes_cb    in          写回调
        app_key             in          回调参
      ```
    + 返回：
        成功 asn_enc_rval_t.encoded记录已编码的字节数
        失败 asn_enc_rval_t.encoded记录 -1
    + 说明：
        对目标语言结构进行编码时，可以通过 asn_TYPE_descriptor_t.der_encoder 来实现
        编码。但对 der_encoder 的调用地址会因目标语言结构类型不同而异， der_encode 
        函数通过对底层进行封装解决了这种困扰。
    + 头文件及实现文件: der_encoder.h       der_encoder.c
  ```c
    asn_enc_rval_t xer_encode(struct asn_TYPE_descriptor_s *type_descriptor,
        void *struct_ptr,
        enum xer_encoder_flags_e xer_flags,
        asn_app_consume_bytes_f *consume_bytes_cb,
        void *app_key);
  ```
    + 功能: 对ASN.1类型对应的目标语言结构进行 XER 编码， xer_decode 是其对应的解码函数
    + 参数：
        ```c
        xer_flags   in   XER_F_BASIC 或 XER_F_CANONICAL
        // 其他参考 der_encode
        ```
    + 返回：
        参考 der_encode
    + 头文件及实现文件: xer_encoder.h       xer_encoder.c
- 解码函数
  ```c
    asn_dec_rval_t ber_decode(struct asn_codec_ctx_s *opt_codec_ctx,
        struct asn_TYPE_descriptor_s *type_descriptor,
        void **struct_ptr,
        const void *buffer,
        size_t size);
  ```
    + 功能: 对DER编码数据进行解码，并使用对应的目标语言结构结构化保存
    + 参数：
      ```c
        opt_codec_ctx       in          限制解码函数对栈的使用，传入限制栈大小的字节数，如果为0则不对栈的使用进行限制
        type_descriptor     in          ASN.1类型标识结构
        struct_ptr          out         目标语言结构的地址，解码函数内部分配动态内存，需要手动释放
        buffer              in          待解码数据
        size                in          待解码数据长度
      ```
    + 返回：
        成功 asn_dec_rval_t.code 为 RC_OK
        再次调用解码函数 asn_dec_rval_t.code 为 RC_WRONG
        失败 asn_dec_rval_t.code 为 RC_FAIL
    + 说明：
        对目标语言结构进行解码时，可以通过 asn_TYPE_descriptor_t.ber_decoder 来实现
        解码。但对 ber_decoder 的调用地址会因目标语言结构类型不同而异， ber_decode 
        函数通过对底层进行封装解决了这种困扰。
    + 头文件及实现文件: ber_decoder.h       ber_decoder.c
  ```c
    asn_dec_rval_t xer_decode(struct asn_codec_ctx_s *opt_codec_ctx,
        struct asn_TYPE_descriptor_s *type_descriptor,
        void **struct_ptr,
        const void *buffer,
        size_t size);
  ```
    + 功能: 对 XER 编码数据进行解码，并使用对应的目标语言结构结构化保存
    + 参数：
        参考 ber_decode
    + 返回：
        参考 ber_decode
    + 头文件及实现文件: xer_decoder.h       xer_decoder.c
- 释放函数
  ```c
    ASN_STRUCT_FREE(asn_TYPE_descriptor_t *td, void *sptr);
    #define ASN_STRUCT_FREE(asn_DEF, ptr)   (asn_DEF).free_struct(&(asn_DEF),ptr,0)
  ```
    + 功能: 对分配在堆中的目标结构内存进行释放。
    + 参数：
      ```c
        td                  in          ASN.1类型标识结构
        sptr                in          指向目标结构内存的指针
      ```
  ```c
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_TYPE_descriptor_t *td, void *sptr);
    #define ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF, ptr) (asn_DEF).free_struct(&(asn_DEF),ptr,1)
  ```
    + 功能: 对分配在栈中的目标结构内存进行释放。
    + 参数：
        参考 ASN_STRUCT_FREE
- 打印函数
  ```c
    int asn_fprint(FILE *stream,
        asn_TYPE_descriptor_t *td,
        const void *struct_ptr);
  ```
    + 功能: 对编码ASN.1化输出
    + 参数：
      ```c
        stream              in          输出流指针
        td                  in          ASN.1类型标识结构
        struct_ptr          in          目标语言结构
      ```
    + 返回：
        成功  0
        失败 -1
    + 说明：
        对目标语言结构进行编码后，可以通过 asn_TYPE_descriptor_t.print_struct 来实
        现对编码内容的可读流输出。但对 print_struct 的调用地址会因目标语言结构类型
        不同而异， asn_fprint 函数通过对底层进行封装解决了这种困扰。
    + 头文件及实现文件: constr_TYPE.h       constr_TYPE.c
  ```c
    int xer_fprint(FILE *stream,
                   struct asn_TYPE_descriptor_td *td, 
                   void *sptr);
  ```
    + 功能: 对编码XML化输出，内部调用 xer_encode 实现
    + 参数：
        参考 asn_fprint
    + 返回：
        参考 asn_fprint
    + 头文件及实现文件: xer_encoder.h       xer_encoder.c