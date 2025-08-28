# Copyright(c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# Add appropriate subdirectory
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(STATUS "Building for Windows")
    add_subdirectory(windows)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "Building for Linux")
    add_subdirectory(linux)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    message(STATUS "Building for ${CMAKE_SYSTEM_NAME}")
    add_subdirectory(macos)

    # Update mpss_SWIFT_SOURCE_FILES variable in the parent scope.
    set(mpss_SWIFT_SOURCE_FILES ${mpss_SWIFT_SOURCE_FILES} PARENT_SCOPE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(STATUS "Building for Android")
    add_subdirectory(android)

    # Update mpss_jar_SOURCE_FILES variable in the parent scope.
    set(mpss_jar_SOURCE_FILES ${mpss_jar_SOURCE_FILES} PARENT_SCOPE)
else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
endif()

# Update mpss_SOURCE_FILES variable in the parent scope.
set(mpss_SOURCE_FILES ${mpss_SOURCE_FILES} PARENT_SCOPE)
