# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# Initialize variables.
set(mpss_INCLUDE_DIRS "")
set(mpss_LINK_LIBRARIES "")

list(APPEND mpss_SOURCE_FILES
    ${CMAKE_CURRENT_LIST_DIR}/backend_registry.cpp
    ${CMAKE_CURRENT_LIST_DIR}/os_backend.cpp
)

# Add OS-native backend (if applicable).
set(MPSS_HAS_OS_BACKEND FALSE)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(STATUS "Building with Windows backend.")
    add_subdirectory(windows)
    set(MPSS_HAS_OS_BACKEND TRUE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    message(STATUS "Building with Apple backend.")
    add_subdirectory(apple)
    set(MPSS_HAS_OS_BACKEND TRUE)

    # Update mpss_SWIFT_SOURCE_FILES variable in the parent scope.
    set(mpss_SWIFT_SOURCE_FILES ${mpss_SWIFT_SOURCE_FILES} PARENT_SCOPE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(STATUS "Building with Android backend.")
    add_subdirectory(android)
    set(MPSS_HAS_OS_BACKEND TRUE)

    # Update mpss_JAR_SOURCE_FILES variable in the parent scope.
    set(mpss_JAR_SOURCE_FILES ${mpss_JAR_SOURCE_FILES} PARENT_SCOPE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "Linux detected. OS backend is not supported.")
    # Linux has no OS-native backend. We will use YubiKey if enabled.
endif()

# Add YubiKey backend (if enabled).
if(MPSS_BACKEND_YUBIKEY)
    message(STATUS "Building with YubiKey PIV backend.")
    add_subdirectory(yubikey)
endif()

# Check that we have at least one backend.
if(NOT MPSS_HAS_OS_BACKEND AND NOT MPSS_BACKEND_YUBIKEY)
    message(FATAL_ERROR "No backend available. Enable MPSS_BACKEND_YUBIKEY or use a platform with an OS backend.")
endif()

# Update variables in parent scope.
set(mpss_SOURCE_FILES ${mpss_SOURCE_FILES} PARENT_SCOPE)
set(mpss_INCLUDE_DIRS ${mpss_INCLUDE_DIRS} PARENT_SCOPE)
set(mpss_LINK_LIBRARIES ${mpss_LINK_LIBRARIES} PARENT_SCOPE)
