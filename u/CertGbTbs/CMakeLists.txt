
cmake_minimum_required(VERSION 3.0.2)

project("certgbtbs test" C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wall -W -fvisibility=default")
set(CMAKE_BUILD_TYPE  DEBUG)

#
# asn1 源文件及头文件路径由外部传入
#
include_directories(${ASN1_SRCS})
aux_source_directory(${ASN1_SRCS} SRCS)

add_executable(coer_decode_crl coer_decode_crl.c ${SRCS})
add_executable(coer_decode_its coer_decode_its.c ${SRCS})
add_executable(coer_encode_crl coer_encode_crl.c ${SRCS})
add_executable(coer_encode_its_ex coer_encode_its_ex.c ${SRCS})
add_executable(coer_encode_its_stack coer_encode_its_stack.c ${SRCS})
add_executable(coer_encode_its coer_encode_its.c ${SRCS})
add_executable(coer_encode_tobesignedcrl coer_encode_tobesignedcrl.c ${SRCS})
# add_executable(coer_Ieee1609Dot2Content coer_Ieee1609Dot2Content.c ${SRCS})
