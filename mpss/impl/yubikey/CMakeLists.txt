# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# libykpiv is found in root CMakeLists.txt and YKPIV_* variables are already set.
if(NOT YKPIV_FOUND)
    message(FATAL_ERROR "YKPIV not found. This file must be included after find_package for ykpiv.")
endif()

# Source files for YubiKey backend
list(APPEND mpss_SOURCE_FILES
    ${CMAKE_CURRENT_LIST_DIR}/mpss_impl.cpp
    ${CMAKE_CURRENT_LIST_DIR}/terminal_interaction_handler.cpp
    ${CMAKE_CURRENT_LIST_DIR}/yk_keypair.cpp
    ${CMAKE_CURRENT_LIST_DIR}/yk_piv.cpp
    ${CMAKE_CURRENT_LIST_DIR}/yk_utils.cpp
)

# The YubiKey backend uses OpenSSL directly (EVP, X509) for verification and
# certificate handling. Ensure it is available even when mpss-openssl is not built.
find_package(OpenSSL 3 CONFIG REQUIRED)

# Add include directories
list(APPEND mpss_INCLUDE_DIRS ${YKPIV_INCLUDE_DIRS})

# Add link libraries
list(APPEND mpss_LINK_LIBRARIES ${YKPIV_LIBRARIES} OpenSSL::Crypto)

# Update parent scope
set(mpss_SOURCE_FILES ${mpss_SOURCE_FILES} PARENT_SCOPE)
set(mpss_INCLUDE_DIRS ${mpss_INCLUDE_DIRS} PARENT_SCOPE)
set(mpss_LINK_LIBRARIES ${mpss_LINK_LIBRARIES} PARENT_SCOPE)
