# Copyright(c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# Add the source files from this directory.
set(mpss_openssl_SOURCE_FILES ${mpss_openssl_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/api.cpp
)

add_subdirectory(utils)
add_subdirectory(provider)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/api.h
        ${CMAKE_CURRENT_LIST_DIR}/defines.h
    DESTINATION
        ${mpss_INCLUDES_INSTALL_DIR}/mpss-openssl
)

# Update mpss_openssl_SOURCE_FILES variable in the parent scope.
set(mpss_openssl_SOURCE_FILES ${mpss_openssl_SOURCE_FILES} PARENT_SCOPE)