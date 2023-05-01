
```s
  mkdir build
  asn1c -no-gen-example ../CertBase.asn1
  cmake .. -DASN1_SRCS=`pwd`
  make
```
