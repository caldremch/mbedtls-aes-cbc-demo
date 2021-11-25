cmake_minimum_required(VERSION 3.21)
project(aes_demo C)

set(CMAKE_C_STANDARD 99)

#add_definitions(-DMBEDTLS_CIPHER_MODE_WITH_PADDING -DMBEDTLS_CIPHER_PADDING_PKCS7)

set(MBEDTSL_INCLUDE ./mbedtls/include)
set(MBEDTSL_LIBRARY ./mbedtls/library)


include_directories(${MBEDTSL_INCLUDE})

add_subdirectory(${MBEDTSL_LIBRARY} MbedTSL)

add_executable(aes_demo main.c)

target_link_libraries(aes_demo mbedcrypto)
