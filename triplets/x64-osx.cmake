# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Delegates to the stock vcpkg triplet and only pins the deployment target, so that
# dependencies are built for the same minimum OS version as MPSS itself. vcpkg reads
# this exclusively from triplet scope; a project-level CMake variable has no effect.
include("$ENV{VCPKG_ROOT}/triplets/community/x64-osx.cmake")

set(VCPKG_OSX_DEPLOYMENT_TARGET 13.3)
