# Copyright(c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMakeFile is not invoked directly.
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    message(FATAL_ERROR "mpss/implementations/macos/CMakeLists.txt must not be invoked directly.")
endif()

# Add the source files from this directory.
set(mpss_SOURCE_FILES ${mpss_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/mpss_impl.cpp
)

# Update mpss_SOURCE_FILES variable in the parent scope.
set(mpss_SOURCE_FILES ${mpss_SOURCE_FILES} PARENT_SCOPE)
