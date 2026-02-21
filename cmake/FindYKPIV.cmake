# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# FindYKPIV
# ---------
#
# Find the libykpiv library (from yubico-piv-tool).
#
# Input variables:
#   YKPIV_ROOT - Path to a custom libykpiv installation directory.
#
# Result variables:
#   YKPIV_FOUND        - TRUE if libykpiv was found.
#   YKPIV_INCLUDE_DIRS - Include directories for libykpiv.
#   YKPIV_LIBRARIES    - Libraries to link against.
#   YKPIV_LIBRARY_DIRS - Library directories (set by pkg-config, may be empty).

set(YKPIV_ROOT "" CACHE PATH "Path to libykpiv installation.")

# Try pkg-config first.
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(YKPIV QUIET ykpiv>=2.0.0)
endif()

# Fall back to manual detection if pkg-config didn't find it.
if(NOT YKPIV_FOUND)
    find_path(YKPIV_INCLUDE_DIR ykpiv/ykpiv.h
        HINTS "${YKPIV_ROOT}/include" "${CMAKE_PREFIX_PATH}/include"
        PATHS /usr/local/include /usr/include)
    find_library(YKPIV_LIBRARY NAMES ykpiv libykpiv
        HINTS "${YKPIV_ROOT}/lib" "${CMAKE_PREFIX_PATH}/lib"
        PATHS /usr/local/lib /usr/lib)

    if(YKPIV_INCLUDE_DIR AND YKPIV_LIBRARY)
        set(YKPIV_FOUND TRUE)
        set(YKPIV_INCLUDE_DIRS "${YKPIV_INCLUDE_DIR}")
        set(YKPIV_LIBRARIES "${YKPIV_LIBRARY}")
    endif()
endif()

# Fix include directory: pkg-config may return .../include/ykpiv
# but we need .../include because we use #include <ykpiv/ykpiv.h>.
if(YKPIV_FOUND)
    set(YKPIV_FIXED_INCLUDE_DIRS)
    foreach(inc_dir ${YKPIV_INCLUDE_DIRS})
        if(inc_dir MATCHES ".*/ykpiv$")
            get_filename_component(parent_dir "${inc_dir}" DIRECTORY)
            list(APPEND YKPIV_FIXED_INCLUDE_DIRS "${parent_dir}")
        else()
            list(APPEND YKPIV_FIXED_INCLUDE_DIRS "${inc_dir}")
        endif()
    endforeach()
    set(YKPIV_INCLUDE_DIRS "${YKPIV_FIXED_INCLUDE_DIRS}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(YKPIV
    REQUIRED_VARS YKPIV_LIBRARIES YKPIV_INCLUDE_DIRS)
