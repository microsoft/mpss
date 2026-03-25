# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# unofficial-libykpiv is found in root CMakeLists.txt via vcpkg.
if(NOT TARGET unofficial::libykpiv::ykpiv)
    message(FATAL_ERROR "unofficial::libykpiv::ykpiv not found. This file must be included after find_package for unofficial-libykpiv.")
endif()

# Source files for YubiKey backend
list(APPEND mpss_SOURCE_FILES
    ${CMAKE_CURRENT_LIST_DIR}/mpss_impl.cpp
    ${CMAKE_CURRENT_LIST_DIR}/terminal_interaction_handler.cpp
    ${CMAKE_CURRENT_LIST_DIR}/yk_backend.cpp
    ${CMAKE_CURRENT_LIST_DIR}/yk_keypair.cpp
    ${CMAKE_CURRENT_LIST_DIR}/yk_piv.cpp
    ${CMAKE_CURRENT_LIST_DIR}/yk_utils.cpp
)

# The YubiKey backend uses OpenSSL directly (EVP, X509) for verification and
# certificate handling. Ensure it is available even when mpss-openssl is not built.
find_package(OpenSSL 3 REQUIRED)

# Add link libraries. The unofficial::libykpiv::ykpiv target carries its own
# include directories and transitive dependencies. OpenSSL::Crypto is also
# linked explicitly because the YubiKey backend uses OpenSSL directly (see above).
list(APPEND mpss_LINK_LIBRARIES unofficial::libykpiv::ykpiv OpenSSL::Crypto)

# Update parent scope
set(mpss_SOURCE_FILES ${mpss_SOURCE_FILES} PARENT_SCOPE)
set(mpss_LINK_LIBRARIES ${mpss_LINK_LIBRARIES} PARENT_SCOPE)
