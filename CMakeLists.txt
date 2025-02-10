# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required (VERSION 3.21)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
    set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT
        "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

# Setting up our options.
option(MPSS_BUILD_SHARED "Build a shared library." NO)
option(MPSS_BUILD_TESTS "Build the test suite." NO)

# Enable tests feature in vcpkg if MPSS_BUILD_TESTS is YES.
if (MPSS_BUILD_TESTS)
    list(APPEND VCPKG_MANIFEST_FEATURES "tests")
endif()

project(mpss VERSION 0.1.0 LANGUAGES CXX)

# All our modules are in cmake/.
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

# Define additional directory path variables.
include(GNUInstallDirs)

# Setup runtime path.
set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Define source tree variables.
set(mpss_INCLUDES_DIR ${CMAKE_CURRENT_LIST_DIR})
set(mpss_CONFIG_H_IN_FILENAME ${mpss_INCLUDES_DIR}/mpss/config.h.in)
set(mpss_CONFIG_IN_FILENAME ${CMAKE_CURRENT_LIST_DIR}/cmake/mpssConfig.cmake.in)

# Define build tree variables.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(mpss_CONFIG_H_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/mpss/config.h)
set(mpss_CONFIG_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/mpssConfig.cmake)
set(mpss_TARGETS_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/mpssTargets.cmake)
set(mpss_CONFIG_VERSION_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/cmake/mpssConfigVersion.cmake)

# Define the install directories.
set(mpss_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/mpss-${mpss_VERSION_MAJOR}.${mpss_VERSION_MINOR})
set(mpss_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/mpss-${mpss_VERSION_MAJOR}.${mpss_VERSION_MINOR})

# Clean config.h from the source dir when configuring.
if (EXISTS ${mpss_CONFIG_H_FILENAME})
    message(STATUS "Cleaning up ${mpss_CONFIG_H_FILENAME}")
    FILE(REMOVE ${mpss_CONFIG_H_FILENAME})
endif()

# List of all source files.
set(mpss_SOURCE_FILES "")
add_subdirectory(mpss)

# Create config.h from config.h.in.
configure_file(${mpss_CONFIG_H_IN_FILENAME} ${mpss_CONFIG_H_FILENAME})

# Set up either static or shared library, depending primarily on MPSS_BUILD_SHARED
# and secondarily on BUILD_SHARED_LIBS.
if (MPSS_BUILD_SHARED)
    set(mpss_LIBRARY_TYPE SHARED)
elseif (BUILD_SHARED_LIBS)
    set(mpss_LIBRARY_TYPE SHARED)
else()
    set(mpss_LIBRARY_TYPE STATIC)
endif()

# If mpss_LIBRARY_TYPE is STATIC, set up static library target.
# If it is SHARED, set up shared library target. Otherwise, error out.
if (mpss_LIBRARY_TYPE STREQUAL "STATIC")
    message(STATUS "Building static library")
    set(mpss_TARGET mpss_static)
    add_library(${mpss_TARGET} ${mpss_LIBRARY_TYPE} ${mpss_SOURCE_FILES})
elseif (mpss_LIBRARY_TYPE STREQUAL "SHARED")
    message(STATUS "Building shared library")
    set(mpss_TARGET mpss_dynamic)
    message(FATAL_ERROR "NOT IMPLEMENTED")
else()
    message(FATAL_ERROR "Invalid value for mpss_LIBRARY_TYPE: ${mpss_LIBRARY_TYPE}")
endif()

# Require C++17 for mpss and downstream.
target_compile_features(${mpss_TARGET} PUBLIC cxx_std_17)

# Internally, mpss indicates a debug build with the macro MPSS_DEBUG_BUILD. This is
# only used in the mpss source files, so it does not need to be set when compiling
# downstream code that includes mpss headers.
target_compile_definitions(${mpss_TARGET} PRIVATE
    $<BUILD_INTERFACE:$<$<CONFIG:Debug>:MPSS_DEBUG_BUILD>>
)

# Platform-specific libraries.
if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(${mpss_TARGET} PRIVATE ncrypt)
endif()

# For debug builds, append "_debug" to the library name.
set_target_properties(${mpss_TARGET} PROPERTIES DEBUG_POSTFIX "_debug")

# Set the VERSION and SOVERSION properties for semantic versioning.
set_target_properties(${mpss_TARGET} PROPERTIES
    VERSION ${mpss_VERSION}
    SOVERSION ${mpss_VERSION_MAJOR}
)

# Set the include directory for build.
target_include_directories(${mpss_TARGET} PUBLIC
    $<BUILD_INTERFACE:${mpss_INCLUDES_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<INSTALL_INTERFACE:${mpss_INCLUDES_INSTALL_DIR}>
)

# Add our target to an export mpssTargets.
if (mpss_LIBRARY_TYPE STREQUAL "STATIC")
    # This allows multiple versions for static libraries since the directories
    # are named according to the version. Works both on Windows and Linux.
    install(TARGETS ${mpss_TARGET} EXPORT mpssTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/mpss-${mpss_VERSION_MAJOR}.${mpss_VERSION_MINOR}
    )
elseif (mpss_LIBRARY_TYPE STREQUAL "DYNAMIC")
    # This allows multiple versions for shared libraries on Linux since the
    # filenames are disambiguated by the version. On Windows, only a single
    # version can be installed at a time. On Windows, import libraries go to
    # ARCHIVE and DLLs to RUNTIME. On Linux, shared libraries go to LIBRARY.
    install(TARGETS ${mpss_TARGET} EXPORT mpssTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )

    # THERE IS A REMAINING PROBLEM: ON WINDOWS THE SOME DIRECTORIES ARE BEING
    # NUMBERED WITH VERSION, SO IT MAY NOT BE CLEAR TO THE USER THAT THERE IS
    # JUST ONE LIBRARY ACTUALLY INSTALLED IN THIS CASE. THIS NEEDS TO BE FIXED.
    message(FATAL_ERROR "NOT IMPLEMENTED")
else()
    message(FATAL_ERROR "Invalid value for mpss_LIBRARY_TYPE: ${mpss_LIBRARY_TYPE}")
endif()

# Create the CMake config file.
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${mpss_CONFIG_IN_FILENAME} ${mpss_CONFIG_FILENAME}
    INSTALL_DESTINATION ${mpss_CONFIG_INSTALL_DIR}
    PATH_VARS mpss_INCLUDES_INSTALL_DIR mpss_CONFIG_INSTALL_DIR
)

# Install our export.
install(
    EXPORT mpssTargets
    NAMESPACE mpss::
    DESTINATION ${mpss_CONFIG_INSTALL_DIR}
)

# Create a version file.
write_basic_package_version_file(
    ${mpss_CONFIG_VERSION_FILENAME}
    VERSION ${mpss_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Install config.h.
install(
    FILES ${mpss_CONFIG_H_FILENAME}
    DESTINATION ${mpss_INCLUDES_INSTALL_DIR}/mpss
)

# Install the config files.
install(
    FILES ${mpss_CONFIG_FILENAME} ${mpss_CONFIG_VERSION_FILENAME}
    DESTINATION ${mpss_CONFIG_INSTALL_DIR}
)

# Export mpssTargets from the build tree so it can be used without installing.
export(
    EXPORT mpssTargets
    NAMESPACE mpss::
    FILE ${mpss_TARGETS_FILENAME}
)

# Test suite.
if (MPSS_BUILD_TESTS)
    find_package(GTest CONFIG REQUIRED)

    set(mpss_TESTS_FILES "")
    add_subdirectory(tests)

    add_executable(mpss_tests ${mpss_TESTS_FILES})
    target_link_libraries(mpss_tests ${mpss_TARGET} GTest::gtest)
endif()
