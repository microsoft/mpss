# Copyright(c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# Add the source files from this directory.
set(mpss_SOURCE_FILES ${mpss_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/mac_api_wrapper.m
    ${CMAKE_CURRENT_LIST_DIR}/mac_keypair.cpp
    ${CMAKE_CURRENT_LIST_DIR}/mac_utils.cpp
    ${CMAKE_CURRENT_LIST_DIR}/mpss_impl.cpp
)

# Add Swift source files from this directory
set(mpss_swift_SOURCE_FILES ${mpss_swift_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/mac_se_wrapper.swift)

# Update mpss_SOURCE_FILES variable in the parent scope.
set(mpss_SOURCE_FILES ${mpss_SOURCE_FILES} PARENT_SCOPE)

# U[pdate mpss_swift_SOURCE_FILES variable in the parent scope.
set(mpss_swift_SOURCE_FILES ${mpss_swift_SOURCE_FILES} PARENT_SCOPE)
