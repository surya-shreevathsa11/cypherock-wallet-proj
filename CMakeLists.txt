cmake_minimum_required(VERSION 3.16)
project(cypherock-wallet LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Boost.Asio (bundled standalone headers in third_party/asio)
set(ASIO_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/third_party/asio)

include(cmake/NanopbCodegen.cmake)
nanopb_add_library(cypherock_proto)

set(TREZOR_DIR ${CMAKE_SOURCE_DIR}/third_party/trezor-crypto)

set(TREZOR_SOURCES
    ${CMAKE_SOURCE_DIR}/libs/crypto/platform_rand.c
    ${TREZOR_DIR}/bignum.c
    ${TREZOR_DIR}/ecdsa.c
    ${TREZOR_DIR}/secp256k1.c
    ${TREZOR_DIR}/curves.c
    ${TREZOR_DIR}/sha2.c
    ${TREZOR_DIR}/sha3.c
    ${TREZOR_DIR}/blake256.c
    ${TREZOR_DIR}/blake2b.c
    ${TREZOR_DIR}/groestl.c
    ${TREZOR_DIR}/hmac.c
    ${TREZOR_DIR}/hmac_drbg.c
    ${TREZOR_DIR}/hasher.c
    ${TREZOR_DIR}/rand.c
    ${TREZOR_DIR}/memzero.c
    ${TREZOR_DIR}/rfc6979.c
    ${TREZOR_DIR}/address.c
    ${TREZOR_DIR}/base58.c
    ${TREZOR_DIR}/ripemd160.c
)

add_library(trezor_crypto STATIC ${TREZOR_SOURCES})
target_include_directories(trezor_crypto PUBLIC ${TREZOR_DIR})
target_compile_definitions(trezor_crypto PUBLIC
    RAND_PLATFORM_INDEPENDENT=1
    USE_PRECOMPUTED_CP=1
    USE_INVERSE_FAST=1
    USE_BIP32_CACHE=0
    USE_BIP39_CACHE=0
)

add_library(cypherock_crypto STATIC
    libs/crypto/ec_ops.cpp
    libs/crypto/scalar256.cpp
    libs/crypto/base_ot.cpp
    libs/crypto/cot_mta.cpp
    libs/crypto/mta_verify.cpp
)
target_include_directories(cypherock_crypto PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${TREZOR_DIR}
)
target_link_libraries(cypherock_crypto PUBLIC trezor_crypto)

add_library(cypherock_net STATIC
    libs/net/protobuf_framing.cpp
    libs/net/tcp_ot_transport.cpp
    libs/net/share_exchange.cpp
)
target_include_directories(cypherock_net PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/generated
    ${ASIO_INCLUDE_DIR}
)
target_compile_definitions(cypherock_net PUBLIC ASIO_STANDALONE)
target_link_libraries(cypherock_net PUBLIC
    cypherock_crypto
    cypherock_proto
)

find_package(Threads REQUIRED)

function(add_cypherock_executable target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE cypherock_net Threads::Threads)
endfunction()

add_cypherock_executable(cypherock_server server/main.cpp)
add_cypherock_executable(cypherock_client client/main.cpp)
