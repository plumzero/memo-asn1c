
```s
  mkdir build
  asn1c -no-gen-example -fcompound-names ../v2x.asn1
  cmake .. -DASN1_SRCS=`pwd`
  make
```
