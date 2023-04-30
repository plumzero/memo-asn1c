
cmake_minimum_required(VERSION 3.0.2)

project("rectangle test" C)

option(BUILD_DLL "build the libasn1.so"       ON)
option(BUILD_OER "build exe for oer directly" OFF)
option(BUILD_DER "build exe for der directly" OFF)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wall -W -fvisibility=default")
set(CMAKE_BUILD_TYPE  DEBUG)

#
# asn1 源文件及头文件路径由外部传入
#
include_directories(${ASN1_SRCS})
aux_source_directory(${ASN1_SRCS} SRCS)

#
# 设置版本
#
set(ASN1_VER "1.0.1")

if (BUILD_DLL)
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
endif (BUILD_DLL)

if (BUILD_OER)
  add_executable(oer_encode Rectangle_oer_encode.c ${SRCS})
  add_executable(oer_decode Rectangle_oer_decode.c ${SRCS})
endif (BUILD_OER)

if (BUILD_DER)
  add_executable(der_encode Rectangle_der_encode.c ${SRCS})
  add_executable(der_decode Rectangle_der_decode.c ${SRCS})
endif (BUILD_DER)
