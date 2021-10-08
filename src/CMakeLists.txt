cmake_minimum_required(VERSION 3.12)

add_library(${PROJECT_NAME})

if(NOT MEOW_CRYPTO_UTILS_STANDALONE_BUILD)
    generate_export_header(${PROJECT_NAME} EXPORT_MACRO_NAME MEOW_CRYPTO_UTILS_SHARED_EXPORT)
endif()

target_sources(${PROJECT_NAME}
        PRIVATE
        crypto_utils.c
        crypto_utils.h)

target_include_directories(${PROJECT_NAME}
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

if(MEOW_CRYPTO_UTILS_ENABLE_INSTALL)
    include(CMakePackageConfigHelpers)

    install(
            TARGETS ${PROJECT_NAME}
            EXPORT ${PROJECT_NAME}Targets
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

    install(
            FILES
            crypto_utils.h
            "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/crypto_utils"
            DESTINATION
            ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

    install(
            FILES
            LICENSE
            README.md
            DESTINATION ${CMAKE_INSTALL_DOCDIR})

    install(
            EXPORT ${PROJECT_NAME}Targets
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})
endif()
