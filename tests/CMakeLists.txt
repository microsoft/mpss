# Copyright(c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMakeFile is not invoked directly.
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    message(FATAL_ERROR "tests/CMakeLists.txt must not be invoked directly.")
endif()

# Add the source files from this directory.
set(mpss_TESTS_FILES ${mpss_TESTS_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/test_runner.cpp
    ${CMAKE_CURRENT_LIST_DIR}/example.cpp
)

# Update mpss_TESTS_FILES variable in the parent scope.
set(mpss_TESTS_FILES ${mpss_TESTS_FILES} PARENT_SCOPE)