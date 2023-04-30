
产生文件
```s
  asn1c -no-gen-example -D src Rectangle.asn1
```

编译
```s
  cmake .. -DASN1_SRCS=/usr/local/asn1c/share/asn1c
```
