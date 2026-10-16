# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.25)

# This is an explicit Android SDK bootstrap helper; normal CMake configure and build commands do
# not invoke it. Developers run it after setting ANDROID_HOME when preparing a workstation or after
# android-base changes. The Android pipeline runs the same helper before configuring MPSS.
#
# android-base is the version source of truth. This script reads its compile API, Build Tools, and
# NDK versions, then asks sdkmanager to install the corresponding packages. sdkmanager is
# idempotent, so packages that are already installed are left unchanged. Set
# MPSS_ANDROID_SDK_PACKAGES_ONLY=ON to print the selected packages without invoking sdkmanager.

# Find android-base without depending on its position in CMakePresets.json.
get_filename_component(mpss_ROOT_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
file(READ "${mpss_ROOT_DIRECTORY}/CMakePresets.json" mpss_PRESET_CONTENTS)
string(JSON mpss_PRESET_COUNT LENGTH "${mpss_PRESET_CONTENTS}" configurePresets)
math(EXPR mpss_LAST_PRESET_INDEX "${mpss_PRESET_COUNT} - 1")

foreach(mpss_PRESET_INDEX RANGE 0 ${mpss_LAST_PRESET_INDEX})
    string(JSON mpss_PRESET_NAME
        GET "${mpss_PRESET_CONTENTS}" configurePresets ${mpss_PRESET_INDEX} name)
    if(mpss_PRESET_NAME STREQUAL "android-base")
        set(mpss_ANDROID_PRESET_INDEX ${mpss_PRESET_INDEX})
        break()
    endif()
endforeach()

if(NOT DEFINED mpss_ANDROID_PRESET_INDEX)
    message(FATAL_ERROR "The android-base configure preset was not found.")
endif()

# Read the package versions directly from the preset.
string(JSON mpss_ANDROID_COMPILE_API
    GET "${mpss_PRESET_CONTENTS}"
    configurePresets ${mpss_ANDROID_PRESET_INDEX} environment MPSS_ANDROID_COMPILE_API)
string(JSON mpss_ANDROID_BUILD_TOOLS_VERSION
    GET "${mpss_PRESET_CONTENTS}"
    configurePresets ${mpss_ANDROID_PRESET_INDEX} environment MPSS_ANDROID_BUILD_TOOLS_VERSION)
string(JSON mpss_ANDROID_NDK_VERSION
    GET "${mpss_PRESET_CONTENTS}"
    configurePresets ${mpss_ANDROID_PRESET_INDEX} environment MPSS_ANDROID_NDK_VERSION)

set(mpss_ANDROID_PLATFORM_PACKAGE "platforms;android-${mpss_ANDROID_COMPILE_API}")
set(mpss_ANDROID_BUILD_TOOLS_PACKAGE
    "build-tools;${mpss_ANDROID_BUILD_TOOLS_VERSION}")
set(mpss_ANDROID_NDK_PACKAGE "ndk;${mpss_ANDROID_NDK_VERSION}")

message(STATUS "Android SDK packages selected by android-base:")
message(STATUS "  platform-tools")
message(STATUS "  ${mpss_ANDROID_PLATFORM_PACKAGE}")
message(STATUS "  ${mpss_ANDROID_BUILD_TOOLS_PACKAGE}")
message(STATUS "  ${mpss_ANDROID_NDK_PACKAGE}")

if(MPSS_ANDROID_SDK_PACKAGES_ONLY)
    return()
endif()

if("$ENV{ANDROID_HOME}" STREQUAL "")
    message(FATAL_ERROR "ANDROID_HOME must point to the Android SDK.")
endif()

if(WIN32)
    set(mpss_ANDROID_SDK_MANAGER
        "$ENV{ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager.bat")
else()
    set(mpss_ANDROID_SDK_MANAGER
        "$ENV{ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager")
endif()

if(NOT EXISTS "${mpss_ANDROID_SDK_MANAGER}")
    message(FATAL_ERROR
        "sdkmanager was not found at ${mpss_ANDROID_SDK_MANAGER}.")
endif()

# Install every package in one sdkmanager invocation and report its combined result.
execute_process(
    COMMAND "${mpss_ANDROID_SDK_MANAGER}"
        "--sdk_root=$ENV{ANDROID_HOME}"
        "platform-tools"
        "${mpss_ANDROID_PLATFORM_PACKAGE}"
        "${mpss_ANDROID_BUILD_TOOLS_PACKAGE}"
        "${mpss_ANDROID_NDK_PACKAGE}"
    RESULT_VARIABLE mpss_SDK_MANAGER_RESULT
)

if(NOT mpss_SDK_MANAGER_RESULT EQUAL 0)
    message(FATAL_ERROR
        "sdkmanager failed with exit code ${mpss_SDK_MANAGER_RESULT}.")
endif()
