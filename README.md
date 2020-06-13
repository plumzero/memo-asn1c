
## asn1 与 json/xml 等的区别(宏观上看)
- json/xml 是对变量名称，变量类型和变量值的编码，asn1 是对变量类型和变量值的编码；
- 使用 asn1 编码后的数据在传输过程中占用的网络带宽相对较小；
- 对多成员数据结构的 asn1 编码必须是按顺序进行的，而 json/xml 则不作此要求；
- asn1 的编码规则相对比较复杂，但实现的功能也更丰富；

## 对 asn1c 的感悟
- confused with, use it, be afraid of, question it, verify it, accept it, just use it

## 学习和测试地址
- [ASN1 语法在线测试](https://asn1.io/asn1playground/)
- [ASN1 编译工具](http://www.obj-sys.com.cn/products-ASN1C.asp)
- [ASN1C github](https://github.com/vlm/asn1c)

## 对 asn1 编码的学习分为两部分
- 建立世界观: 对语法的学习
	+ asn1练习.asn1   -  敲一敲它大致语法，只看是没用的；
	+ asn1结构.md     - 不求大求全，但对于常用的，还是要细致了解的；
	+ asn1编码规则.md - 仅作了解，体会 ASN.1 编码思想，并不作深入研究； 
- 掌握方法论: 对 asn1c 的学习
	+ 使用asn1c命令.md - asn1c的编译及常用命令使用；
	+ 使用asn1c编码.md - 快速入门，编码注意，常用结构；
	+ 使用asn1c问题.md - 坑及解决办法；提醒是坑但暂时不知道怎么解决或没有提供解决办法；

## 对 asn1c 库的认识
- asn1c 对 asn1 语法并没有完全实现，对有些语法的实现也存在一些问题；
- asn1c 的作者已经挂机好久了，很多 issue 没有进行处理，即使有些 issue 确实是 bug ;
- 虽然 asn1c 不是万能的，但对于 c/c++ 程序员来说，它是实现 asn1 编码的最好选择。asn1c
  不能解决所有的问题，但可以解决大部分的问题。
- 个人对 asn1c
    + confused with it
    + try use it
    + be afraid of something bad would happen
    + overcome and verify it
    + understand it
    + accept it
    + just use it like an idiot
  