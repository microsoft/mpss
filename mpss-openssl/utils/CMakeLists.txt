# Copyright(c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# Add the source files from this directory.
set(mpss_openssl_SOURCE_FILES ${mpss_openssl_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/names.cpp
    ${CMAKE_CURRENT_LIST_DIR}/ossl_helpers.cpp
)

# Update mpss_openssl_SOURCE_FILES variable in the parent scope.
set(mpss_openssl_SOURCE_FILES ${mpss_openssl_SOURCE_FILES} PARENT_SCOPE)
