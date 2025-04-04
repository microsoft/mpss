# Copyright(c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# Add the source files from this directory.
set(mpss_SOURCE_FILES ${mpss_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/mpss.cpp
)

add_subdirectory(implementations)
add_subdirectory(utils)

install(
    FILES
    ${CMAKE_CURRENT_LIST_DIR}/mpss.h
    ${CMAKE_CURRENT_LIST_DIR}/algorithm.h
    DESTINATION
    ${mpss_INCLUDES_INSTALL_DIR}/mpss
)

# Update mpss_SOURCE_FILES variable in the parent scope.
set(mpss_SOURCE_FILES ${mpss_SOURCE_FILES} PARENT_SCOPE)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(mpss_swift_SOURCE_FILES ${mpss_swift_SOURCE_FILES} PARENT_SCOPE)
endif()
