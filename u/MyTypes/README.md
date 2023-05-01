
```s
  mkdir build
  asn1c -no-gen-example ../MyTypes.asn1
  cmake .. -DASN1_SRCS=`pwd`
  make
```
