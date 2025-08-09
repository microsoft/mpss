# Copyright(c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# In any case, compile the test runner.
set(mpss_TESTS_FILES ${mpss_TESTS_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/test_runner.cpp
)

# Conditionally add tests depending on what is being built.
if (TARGET ${mpss_TARGET})
    set(mpss_TESTS_FILES ${mpss_TESTS_FILES}
        ${CMAKE_CURRENT_LIST_DIR}/mpss_tests.cpp
    )
endif()
if (TARGET ${mpss_openssl_TARGET})
    set(mpss_TESTS_FILES ${mpss_TESTS_FILES}
        ${CMAKE_CURRENT_LIST_DIR}/mpss_openssl_tests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/mpss_openssl_e2e_test.cpp
    )
endif()

# Update mpss_TESTS_FILES variable in the parent scope.
set(mpss_TESTS_FILES ${mpss_TESTS_FILES} PARENT_SCOPE)
