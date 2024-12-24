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

# Create the library target.
add_library(mpss ${mpss_LIBRARY_TYPE} ${mpss_SOURCE_FILES})

# Internally, mpss indicates a debug build with the macro MPSS_DEBUG_BUILD. This is
# only used in the mpss source files, so it does not need to be set when compiling
# downstream code that includes mpss headers.
target_compile_definitions(mpss PRIVATE
    $<BUILD_INTERFACE:$<$<CONFIG:Debug>:MPSS_DEBUG_BUILD>>
)

# Set the platform macro based on the target platform.
target_compile_definitions(mpss PRIVATE
    $<BUILD_INTERFACE:$<$<PLATFORM_ID:Windows>:MPSS_PLATFORM_WINDOWS>>
    $<BUILD_INTERFACE:$<$<PLATFORM_ID:Linux>:MPSS_PLATFORM_LINUX>>
    $<BUILD_INTERFACE:$<$<PLATFORM_ID:Darwin>:MPSS_PLATFORM_MACOS>>
    $<BUILD_INTERFACE:$<$<PLATFORM_ID:iOS>:MPSS_PLATFORM_IOS>>
    $<BUILD_INTERFACE:$<$<PLATFORM_ID:Android>:MPSS_PLATFORM_ANDROID>>
)

# For debug builds, append "-d" to the library name.
set_target_properties(mpss PROPERTIES DEBUG_POSTFIX "-d")

# Set the VERSION and SOVERSION properties for semantic versioning.
set_target_properties(mpss PROPERTIES
    VERSION ${mpss_VERSION}
    SOVERSION ${mpss_VERSION_MAJOR}
)

# Set the include directory for build.
target_include_directories(mpss PUBLIC
    $<BUILD_INTERFACE:${mpss_INCLUDES_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<INSTALL_INTERFACE:${mpss_INCLUDES_INSTALL_DIR}>
)

# Add mpss to export mpssTargets.
install(TARGETS mpss EXPORT mpssTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

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
    target_link_libraries(mpss_tests mpss GTest::gtest)
endif()
