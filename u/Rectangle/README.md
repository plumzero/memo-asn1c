
```s
  mkdir build
  asn1c -no-gen-example ../Rectangle.asn1
  cmake .. -DASN1_SRCS=`pwd`
  make
```
