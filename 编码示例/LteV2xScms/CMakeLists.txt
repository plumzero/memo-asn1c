cmake_minimum_required(VERSION 3.0.2)

project("asn1 test" C CXX)

option(BUILD_DYNAMIC_ASN1       "build the libasn1.so"  ON)
option(BUILD_OER_EXECUTE        "build executable program about oer directly"   ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -Wall -W -std=c++11")
set(CMAKE_BUILD_TYPE  DEBUG)

# asn1 源文件及头文件路径由外部传入
include_directories(${ASN1_SRCS})
aux_source_directory(${ASN1_SRCS} SRCS)

if (BUILD_DYNAMIC_ASN1)
    set(soname asn1)
    add_library(${soname} SHARED ${SRCS})

    add_executable(relyon_coer_decoder coer_decoder.cpp)
    target_link_libraries(relyon_coer_decoder asn1)
    
    add_executable(relyon_test_encoder test_encoder.cpp)
    target_link_libraries(relyon_test_encoder asn1)
endif (BUILD_DYNAMIC_ASN1)

if (BUILD_OER_EXECUTE)
    add_executable(coer_decoder ${SRCS} coer_decoder.cpp)
    add_executable(test_encoder ${SRCS} test_encoder.cpp)
endif (BUILD_OER_EXECUTE)