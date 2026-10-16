# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Delegates to the stock vcpkg triplet but builds OpenSSL as a shared library, so that MPSS and
# the application share one OpenSSL instead of each embedding a copy.
include("$ENV{VCPKG_ROOT}/triplets/arm64-android.cmake")

if(PORT STREQUAL "openssl")
    set(VCPKG_LIBRARY_LINKAGE dynamic)
endif()
