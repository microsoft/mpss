# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.25)

# Integrated mode: select the common tests, then let each platform own its runner
# and packaging.
if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(mpss_TESTS_FILES "${CMAKE_CURRENT_LIST_DIR}/test_entry.cpp")
    set(mpss_TESTS_LINK_LIBRARIES GTest::gtest)

    if(TARGET ${mpss_TARGET})
        list(APPEND mpss_TESTS_FILES "${CMAKE_CURRENT_LIST_DIR}/mpss_tests.cpp")
        if(MPSS_WITH_SERIALIZATION)
            list(APPEND mpss_TESTS_FILES "${CMAKE_CURRENT_LIST_DIR}/serialization_tests.cpp")
            list(APPEND mpss_TESTS_LINK_LIBRARIES OpenSSL::Crypto)
        endif()
    endif()
    if(TARGET ${mpss_openssl_TARGET})
        list(APPEND mpss_TESTS_FILES
            "${CMAKE_CURRENT_LIST_DIR}/mpss_openssl_tests.cpp"
            "${CMAKE_CURRENT_LIST_DIR}/mpss_openssl_e2e_test.cpp"
        )
        # mpss comes transitively through mpss_openssl's PUBLIC dependency.
        list(APPEND mpss_TESTS_LINK_LIBRARIES ${mpss_openssl_TARGET})

        # libssl is a test-only dependency: the tests drive a TLS handshake, while the provider
        # itself links libcrypto alone and must keep doing so.
        find_package(OpenSSL 3.2 REQUIRED)
        list(APPEND mpss_TESTS_LINK_LIBRARIES OpenSSL::SSL)
    elseif(TARGET ${mpss_TARGET})
        list(APPEND mpss_TESTS_LINK_LIBRARIES ${mpss_TARGET})
    endif()

    if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
        add_subdirectory(ios)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
        add_subdirectory(android)
    else()
        add_executable(mpss_tests
            ${mpss_TESTS_FILES}
            "${CMAKE_CURRENT_LIST_DIR}/test_runner.cpp"
        )
        target_link_libraries(mpss_tests PRIVATE ${mpss_TESTS_LINK_LIBRARIES})

        if(TARGET mpss_openssl)
            target_compile_definitions(mpss_tests PRIVATE
                MPSS_TEST_PROVIDER_MODULE="$<TARGET_FILE:mpss_openssl>"
            )
        endif()

        # gmock-win32 patches the running executable's import table, so the mock tests need the
        # static backend and their own executable: the patching is process-global and clashes with
        # the OpenSSL provider's algorithm probing.
        if(WIN32 AND MPSS_BUILD_MPSS_CORE_STATIC AND MPSS_BUILD_WIN32_MOCK_TESTS AND TARGET ${mpss_TARGET})
            include(FetchContent)
            FetchContent_Declare(gmock_win32_fetch
                GIT_REPOSITORY https://github.com/smalti/gmock-win32.git
                GIT_TAG 8f7ac8325a6ab4f93bb959621c8e700304b6f739 # 1.3.0
            )
            # Upstream ships no CMakeLists, so this only downloads the sources.
            FetchContent_MakeAvailable(gmock_win32_fetch)

            add_library(gmock_win32 STATIC "${gmock_win32_fetch_SOURCE_DIR}/src/gmock-win32.cpp")
            target_include_directories(gmock_win32 PUBLIC "${gmock_win32_fetch_SOURCE_DIR}/include")
            target_link_libraries(gmock_win32 PUBLIC GTest::gmock)
            target_compile_features(gmock_win32 PUBLIC cxx_std_20)

            add_executable(mpss_win32_mock_tests "${CMAKE_CURRENT_LIST_DIR}/mpss_win32_mock_tests.cpp")
            target_link_libraries(mpss_win32_mock_tests
                PRIVATE ${mpss_TARGET} GTest::gtest GTest::gmock gmock_win32)
            target_include_directories(mpss_win32_mock_tests PRIVATE "${CMAKE_CURRENT_LIST_DIR}/..")
        elseif(MPSS_BUILD_WIN32_MOCK_TESTS)
            # Requested but not buildable here. Without a message the configure still succeeds, so
            # the suite looks like it ran.
            if(NOT WIN32)
                message(STATUS "Win32 mock tests skipped: they patch the NCrypt import table, so they apply to Windows only.")
            elseif(NOT MPSS_BUILD_MPSS_CORE_STATIC)
                message(STATUS "Win32 mock tests skipped: they need the static core library, and this build is shared.")
            else()
                message(STATUS "Win32 mock tests skipped: the core target '${mpss_TARGET}' is not part of this build.")
            endif()
        endif()
    endif()

    return()
endif()

# Standalone mode: build the tests against an installed mpss. An mpss build tree is not enough;
# find_package expects the installed layout.
#
# Dependencies must already be resolvable. The tests directory has no vcpkg manifest, so manifest
# mode is turned off and the dependency prefix is supplied instead, for example the vcpkg_installed
# tree of an existing MPSS build.
#
# Usage:
#   cmake -S tests -B build_tests -G Ninja \
#         -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
#         -DVCPKG_MANIFEST_MODE=OFF \
#         -DCMAKE_PREFIX_PATH=/path/to/vcpkg_installed/<triplet> \
#         -Dmpss_ROOT=/path/to/mpss/install/dir \
#         -DCMAKE_BUILD_TYPE=<Debug|Release>
#   cmake --build build_tests --target mpss_tests
project(mpss_tests LANGUAGES CXX)

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(FATAL_ERROR
        "Standalone Android tests are not supported. Configure the top-level "
        "MPSS project with MPSS_BUILD_TESTS=ON.")
endif()

# Accept MPSS_ROOT as a case-insensitive alias for mpss_ROOT.
if(DEFINED MPSS_ROOT AND NOT DEFINED mpss_ROOT)
    set(mpss_ROOT "${MPSS_ROOT}")
endif()

find_package(mpss REQUIRED)
find_package(GTest CONFIG REQUIRED)

# Always compile the reusable entry point and desktop runner.
set(mpss_TESTS_SOURCES test_entry.cpp test_runner.cpp)

# Conditionally add tests depending on what the installed mpss provides.
if(MPSS_CORE_FOUND)
    list(APPEND mpss_TESTS_SOURCES mpss_tests.cpp)
    if(MPSS_WITH_SERIALIZATION)
        list(APPEND mpss_TESTS_SOURCES serialization_tests.cpp)
    endif()
endif()
if(MPSS_OPENSSL_FOUND)
    list(APPEND mpss_TESTS_SOURCES
        mpss_openssl_tests.cpp
        mpss_openssl_e2e_test.cpp
    )
endif()

add_executable(mpss_tests ${mpss_TESTS_SOURCES})
target_link_libraries(mpss_tests PRIVATE GTest::gtest)
if(MPSS_WITH_SERIALIZATION)
    target_link_libraries(mpss_tests PRIVATE OpenSSL::Crypto)
endif()

# Link against the best available mpss target. mpss-openssl pulls in mpss
# transitively through its PUBLIC dependency, so we only need one link.
if(MPSS_OPENSSL_FOUND)
    if(TARGET mpss::mpss_openssl)
        target_link_libraries(mpss_tests PRIVATE mpss::mpss_openssl)
        target_compile_definitions(mpss_tests PRIVATE
            MPSS_TEST_PROVIDER_MODULE="$<TARGET_FILE:mpss::mpss_openssl>"
        )
    else()
        target_link_libraries(mpss_tests PRIVATE mpss::mpss_openssl_static)
    endif()

    # The same test-only libssl dependency as the integrated branch above.
    find_package(OpenSSL 3.2 REQUIRED)
    target_link_libraries(mpss_tests PRIVATE OpenSSL::SSL)
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
