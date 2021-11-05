cmake_minimum_required(VERSION 3.20)
project(openssl_crypto)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL 1.1 REQUIRED)

add_library(openssl_crypto STATIC single-block-crypto.cpp)

target_link_libraries(openssl_crypto OpenSSL::Crypto)
