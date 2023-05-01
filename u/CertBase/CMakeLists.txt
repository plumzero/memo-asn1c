
cmake_minimum_required(VERSION 3.0.2)

project("certbase test" C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wall -W -fvisibility=default")
set(CMAKE_BUILD_TYPE  DEBUG)

#
# asn1 源文件及头文件路径由外部传入
#
include_directories(${ASN1_SRCS})
aux_source_directory(${ASN1_SRCS} SRCS)

add_executable(CertBase CertBase.c ${SRCS})
