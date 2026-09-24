cmake_minimum_required(VERSION 3.16)

project(partner_signed_client
    VERSION 0.1.0
    DESCRIPTION "C++ port of the BanglaReels partner signed-request client (HMAC + Ed25519)"
    LANGUAGES CXX)

set(_psc_top_level OFF)
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(_psc_top_level ON)
endif()

option(PARTNER_SIGNED_CLIENT_BUILD_EXAMPLES "Build the handoff example" ${_psc_top_level})
option(PARTNER_SIGNED_CLIENT_BUILD_TESTS "Build the compatibility tests" ${_psc_top_level})
option(PARTNER_SIGNED_CLIENT_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

# ---- dependencies ------------------------------------------------------------------------------

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(CURL REQUIRED)

# nlohmann/json (header-only, MIT): use an installed copy if there is one, otherwise download it.
find_package(nlohmann_json 3.11 QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
        URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# ---- warnings ----------------------------------------------------------------------------------

add_library(partner_signed_client_warnings INTERFACE)
if(MSVC)
    target_compile_options(partner_signed_client_warnings INTERFACE /W4
        $<$<BOOL:${PARTNER_SIGNED_CLIENT_WARNINGS_AS_ERRORS}>:/WX>)
else()
    target_compile_options(partner_signed_client_warnings INTERFACE -Wall -Wextra -Wpedantic
        $<$<BOOL:${PARTNER_SIGNED_CLIENT_WARNINGS_AS_ERRORS}>:-Werror>)
endif()

# ---- library -----------------------------------------------------------------------------------

add_library(partner_signed_client
    src/crypto.cpp
    src/verifier.cpp
    src/client.cpp
    src/curl_transport.cpp)
add_library(danumai::partner_signed_client ALIAS partner_signed_client)

target_include_directories(partner_signed_client PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_compile_features(partner_signed_client PUBLIC cxx_std_17)
target_link_libraries(partner_signed_client
    PUBLIC nlohmann_json::nlohmann_json
    PRIVATE OpenSSL::Crypto CURL::libcurl $<BUILD_INTERFACE:partner_signed_client_warnings>)

# ---- example -----------------------------------------------------------------------------------

if(PARTNER_SIGNED_CLIENT_BUILD_EXAMPLES)
    add_executable(handoff_example examples/handoff.cpp)
    target_link_libraries(handoff_example PRIVATE partner_signed_client partner_signed_client_warnings)
endif()

# ---- tests -------------------------------------------------------------------------------------

if(PARTNER_SIGNED_CLIENT_BUILD_TESTS)
    enable_testing()
    add_executable(compatibility_tests tests/compatibility_tests.cpp)
    target_link_libraries(compatibility_tests PRIVATE partner_signed_client partner_signed_client_warnings)
    add_test(NAME compatibility_tests COMMAND compatibility_tests)
endif()
