
*就是因为能下出那样好的棋，所以才无法放弃成为职业棋士的梦想。*

### asn1 与 json/xml 等的区别(宏观上看)

- json/xml 是对变量名称，变量类型和变量值的编码，asn1 是对变量类型和变量值的编码
- 使用 asn1 编码后的数据在传输过程中占用的网络带宽相对较小
- 对多成员数据结构的 asn1 编码必须是按顺序进行的，而 json/xml 则不作此要求
- asn1 的编码规则相对比较复杂，但实现的功能也更丰富

### 学习和测试地址

- [ASN1 语法在线测试](https://asn1.io/asn1playground/)
- [ASN1 编译工具](http://www.obj-sys.com.cn/products-ASN1C.asp)
- [ASN1C github](https://github.com/vlm/asn1c)

### 对 asn1 编码的学习分为两部分

建立世界观: 对语法的学习
- [语法练习](0a_语法练习.md)
- [语法结构](0b_语法结构.md)
- [编码规则](0c_编码规则.md)

掌握方法论: 对工具的学习
- [编译安装](01_编译安装.md)
- [使用命令](02_使用命令.md)
- [接口函数](03_接口函数.md)
- [使用问题](04_使用问题.md)

[这里](u)提供了一些示例程序，但是因为某些原因，有些未必编译通过，开发者可以自己尝试解决。

### 对 asn1c 库的认识

- asn1c 对 asn1 语法并没有完全实现，对有些语法的实现也存在一些问题。
- asn1c 的作者已经挂机好久了，很多 issue 没有进行处理，即使有些 issue 确实是 bug。
- 虽然 asn1c 不是万能的，但对于 c/c++ 程序员来说，它是实现 asn1 编码的最好选择。asn1c 不能解决所有的问题，但可以解决大部分的问题。
