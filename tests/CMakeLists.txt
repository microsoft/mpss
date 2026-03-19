# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.25)

# When invoked as a subdirectory, just collect source files and return.
if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # In any case, compile the test runner.
    list(APPEND mpss_TESTS_FILES "${CMAKE_CURRENT_LIST_DIR}/test_runner.cpp")

    # Conditionally add tests depending on what is being built.
    if(TARGET ${mpss_TARGET})
        list(APPEND mpss_TESTS_FILES "${CMAKE_CURRENT_LIST_DIR}/mpss_tests.cpp")
    endif()
    if(TARGET ${mpss_openssl_TARGET})
        list(APPEND mpss_TESTS_FILES
            "${CMAKE_CURRENT_LIST_DIR}/mpss_openssl_tests.cpp"
            "${CMAKE_CURRENT_LIST_DIR}/mpss_openssl_e2e_test.cpp"
        )
    endif()

    # Update mpss_TESTS_FILES variable in the parent scope.
    set(mpss_TESTS_FILES ${mpss_TESTS_FILES} PARENT_SCOPE)
    return()
endif()

# Standalone mode: build tests against an installed or build-tree mpss.
#
# Usage:
#   cmake -S tests -B build_tests \
#         -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT_DIR/scripts/buildsystems/vcpkg.cmake \
#         -Dmpss_ROOT=/path/to/mpss/install/dir \
#         -DCMAKE_BUILD_TYPE=<Debug|Release>
#   cmake --build build_tests --target mpss_tests
project(mpss_tests LANGUAGES CXX)

# Accept MPSS_ROOT as a case-insensitive alias for mpss_ROOT.
if(DEFINED MPSS_ROOT AND NOT DEFINED mpss_ROOT)
    set(mpss_ROOT "${MPSS_ROOT}")
endif()

find_package(mpss REQUIRED)
find_package(GTest CONFIG REQUIRED)

# Always compile the test runner.
set(mpss_TESTS_SOURCES test_runner.cpp)

# Conditionally add tests depending on what the installed mpss provides.
if(MPSS_CORE_FOUND)
    list(APPEND mpss_TESTS_SOURCES mpss_tests.cpp)
endif()
if(MPSS_OPENSSL_FOUND)
    list(APPEND mpss_TESTS_SOURCES
        mpss_openssl_tests.cpp
        mpss_openssl_e2e_test.cpp
    )
endif()

add_executable(mpss_tests ${mpss_TESTS_SOURCES})
target_link_libraries(mpss_tests PRIVATE GTest::gtest)

# Link against the best available mpss target. mpss-openssl pulls in mpss
# transitively through its PUBLIC dependency, so we only need one link.
if(MPSS_OPENSSL_FOUND)
    if(TARGET mpss::mpss_openssl)
        target_link_libraries(mpss_tests PRIVATE mpss::mpss_openssl)
    else()
        target_link_libraries(mpss_tests PRIVATE mpss::mpss_openssl_static)
    endif()
elseif(MPSS_CORE_FOUND)
    if(TARGET mpss::mpss)
        target_link_libraries(mpss_tests PRIVATE mpss::mpss)
    else()
        target_link_libraries(mpss_tests PRIVATE mpss::mpss_static)
    endif()
endif()

# Add the parent directory to the include path so that test-local headers
# (included via paths like "mpss/../tests/...") resolve correctly.
target_include_directories(mpss_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/..")
