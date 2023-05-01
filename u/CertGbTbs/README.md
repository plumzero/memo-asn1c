
```s
  mkdir build
  asn1c -no-gen-example ../GB_T.asn1
  cmake .. -DASN1_SRCS=`pwd`
  make
```
