# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required (VERSION 3.16)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT
	"$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project(mpss VERSION 0.0.1 LANGUAGES CXX)

# All our modules are in cmake/.
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

# Only C++17 or higher is supported.
if (CMAKE_CXX_STANDARD LESS 17)
  message(FATAL_ERROR "C++17 or higher is required.")
endif()

# Define additional directory path variables.
include(GNUInstallDirs)

# Setup runtime path.
set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Define source tree variables.
set(mpss_INCLUDES_DIR ${CMAKE_CURRENT_LIST_DIR})
set(mpss_CONFIG_H_IN_FILENAME ${mpss_INCLUDES_DIR}/mpss/config.h.in)

# Define build tree variables.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(mpss_CONFIG_H_FILENAME ${CMAKE_CURRENT_BINARY_DIR}/mpss/config.h)

# Clean config.h from the source dir when configuring.
if(EXISTS ${mpss_CONFIG_H_FILENAME})
  message(STATUS "Cleaning up ${mpss_CONFIG_H_FILENAME}")
  FILE(REMOVE ${mpss_CONFIG_H_FILENAME})
endif()

# List of all source files.
set(mpss_SOURCE_FILES "")
add_subdirectory(mpss)

# Print ${mpss_SOURCE_FILES} for debugging.
message(STATUS "mpss_SOURCE_FILES: ${mpss_SOURCE_FILES}")

# Create config.h from config.h.in.
configure_file(${mpss_CONFIG_H_IN_FILENAME} ${mpss_CONFIG_H_FILENAME})

# For now, an executable target.
add_executable(mpss ${mpss_SOURCE_FILES})

# Set the VERSION and SOVERSION properties for semantic versioning.
set_target_properties(mpss PROPERTIES
  VERSION ${mpss_VERSION}
  SOVERSION ${mpss_VERSION_MAJOR}
)

# Set the include directory for build.
target_include_directories(mpss PUBLIC
	$<BUILD_INTERFACE:${mpss_INCLUDES_DIR}>
	$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
)
