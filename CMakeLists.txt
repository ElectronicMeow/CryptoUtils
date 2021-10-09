cmake_minimum_required(VERSION 3.12)

project(MeowCryptoUtils C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

include(GenerateExportHeader)

set(MEOW_CRYPTO_UTILS_STANDALONE_BUILD OFF)
if(PROJECT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(MEOW_CRYPTO_UTILS_STANDALONE_BUILD ON)
endif()

option(MEOW_CRYPTO_UTILS_ENABLE_INSTALL "${PROJECT_NAME}: Enable install" ${MEOW_CRYPTO_UTILS_STANDALONE_BUILD})
option(MEOW_CRYPTO_UTILS_ENABLE_TESTS "${PROJECT_NAME}: Enable tests" ${MEOW_CRYPTO_UTILS_STANDALONE_BUILD})
option(MEOW_CRYPTO_UTILS_ENABLE_WERROR "${PROJECT_NAME}: Treat warnings as errors" OFF)

if(MEOW_CRYPTO_UTILS_ENABLE_INSTALL)
    include(GNUInstallDirs)
endif()

if(MEOW_CRYPTO_UTILS_STANDALONE_BUILD)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(
                -Wall
                -Wextra
                -pedantic
                $<$<BOOL:${MEOW_CRYPTO_UTILS_ENABLE_WERROR}>:-Werror>)
    elseif(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
        add_compile_options(
                /W4
                $<$<BOOL:${MEOW_CRYPTO_UTILS_ENABLE_WERROR}>:/WX>)
    endif()
endif()

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(GMP REQUIRED)

message("Found GMP Library: ${GMP_LIBRARIES}")

add_subdirectory(src)
