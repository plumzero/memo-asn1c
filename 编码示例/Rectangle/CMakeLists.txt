cmake_minimum_required(VERSION 3.0.2)

project("asn1 test" C)

option(BUILD_DYNAMIC_ASN1       "build the libasn1.so"  ON)
option(BUILD_OER_EXECUTE        "build executable program about oer directly"   ON)
option(BUILD_DER_EXECUTE        "build executable program about der directly"   ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wall -W")
set(CMAKE_BUILD_TYPE  DEBUG)

# asn1 源文件及头文件路径由外部传入
include_directories(${ASN1_SRCS})
aux_source_directory(${ASN1_SRCS} SRCS)

# 设置缺省版本
if (NOT ASN1_VER)
    set(ASN1_VER "0.9.29")
endif(ASN1_VER)

if (BUILD_DYNAMIC_ASN1)
    set(soname asn1)
    add_library(${soname} SHARED ${SRCS})
    set_target_properties(${soname} PROPERTIES VERSION ${ASN1_VER})
    
    add_executable(relyon_oer_encode Rectangle_oer_encode.c)
    target_link_libraries(relyon_oer_encode asn1)

    add_executable(relyon_oer_decode Rectangle_oer_decode.c)
    target_link_libraries(relyon_oer_decode asn1)
    
    add_executable(relyon_der_encode Rectangle_der_encode.c)
    target_link_libraries(relyon_der_encode asn1)

    add_executable(relyon_der_decode Rectangle_der_decode.c)
    target_link_libraries(relyon_der_decode asn1)
endif (BUILD_DYNAMIC_ASN1)

if (BUILD_OER_EXECUTE)
    add_executable(oer_encode Rectangle_oer_encode.c ${SRCS})
    add_executable(oer_decode Rectangle_oer_decode.c ${SRCS})
    
    add_executable(der_encode Rectangle_der_encode.c ${SRCS})
    add_executable(der_decode Rectangle_der_decode.c ${SRCS})
endif (BUILD_OER_EXECUTE)