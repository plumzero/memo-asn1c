cmake_minimum_required(VERSION 3.0.2)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -Wall -W")
set(CMAKE_BUILD_TYPE  DEBUG)

# asn1 源文件及头文件路径由外部传入
include_directories(${ASN1_SRCS})
aux_source_directory(${ASN1_SRCS} SRCS)

add_executable(coer_decoder ${SRCS} coer_decoder.cpp)

add_executable(test_encoder ${SRCS} test_encoder.cpp)