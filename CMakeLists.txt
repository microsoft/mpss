# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.25)

# Setting up our options. The library types (static/shared) are mutually exclusive.
option(MPSS_BUILD_MPSS_CORE_STATIC "Build the mpss core static library." NO)
option(MPSS_BUILD_MPSS_CORE_SHARED "Build the mpss core shared library." NO)
option(MPSS_BUILD_MPSS_OPENSSL_STATIC "Build the OpenSSL provider static library." NO)
option(MPSS_BUILD_MPSS_OPENSSL_SHARED "Build the mpss OpenSSL provider shared library." NO)
option(MPSS_BUILD_TESTS "Build the test suite." NO)
option(MPSS_BACKEND_YUBIKEY "Build with YubiKey PIV backend." NO)
option(MPSS_WITH_SERIALIZATION "Build key-reference DER and PEM serialization using OpenSSL." NO)
option(MPSS_ENABLE_HARDENING "Enable security hardening compile and link flags." YES)

# Drives the provider fallbacks, which real hardware cannot be made to fail on demand.
# Windows and a static backend only.
option(MPSS_BUILD_WIN32_MOCK_TESTS "Build the gmock-win32 NCrypt mock test executable." NO)

# Manifest features are additive requests, including when configuring this checkout directly.
# Use normal variables so removing a feature does not latch its implied options in the cache.
if("serialization" IN_LIST VCPKG_MANIFEST_FEATURES)
    set(MPSS_WITH_SERIALIZATION ON)
endif()

if("yubikey" IN_LIST VCPKG_MANIFEST_FEATURES)
    set(MPSS_BACKEND_YUBIKEY ON)
endif()

if("tests" IN_LIST VCPKG_MANIFEST_FEATURES)
    set(MPSS_BUILD_TESTS ON)
endif()

# If BUILD_SHARED_LIBS is set and no explicit library type options were provided,
# default to building shared libraries. Explicit -D options take precedence.
if(BUILD_SHARED_LIBS)
    set(_mpss_explicit_options OFF)
    if(MPSS_BUILD_MPSS_CORE_STATIC OR MPSS_BUILD_MPSS_CORE_SHARED
        OR MPSS_BUILD_MPSS_OPENSSL_STATIC OR MPSS_BUILD_MPSS_OPENSSL_SHARED)
        set(_mpss_explicit_options ON)
    endif()

    if(NOT _mpss_explicit_options)
        set(MPSS_BUILD_MPSS_CORE_SHARED ON)
        set(MPSS_BUILD_MPSS_OPENSSL_SHARED ON)
    endif()
endif()

# Validate mutual exclusivity.
if(MPSS_BUILD_MPSS_CORE_STATIC AND MPSS_BUILD_MPSS_CORE_SHARED)
    message(FATAL_ERROR
        "Cannot build both static and shared mpss core libraries.")
elseif(NOT MPSS_BUILD_MPSS_CORE_STATIC AND NOT MPSS_BUILD_MPSS_CORE_SHARED)
    message(STATUS "Neither STATIC nor SHARED build specified. Defaulting to STATIC.")
    set(MPSS_BUILD_MPSS_CORE_STATIC ON CACHE BOOL "Build the static mpss core library." FORCE)
endif()

# An explicit provider linkage wins; otherwise the manifest feature follows the core's linkage.
if("openssl" IN_LIST VCPKG_MANIFEST_FEATURES
    AND NOT MPSS_BUILD_MPSS_OPENSSL_STATIC AND NOT MPSS_BUILD_MPSS_OPENSSL_SHARED)
    if(MPSS_BUILD_MPSS_CORE_SHARED)
        set(MPSS_BUILD_MPSS_OPENSSL_SHARED ON)
    else()
        set(MPSS_BUILD_MPSS_OPENSSL_STATIC ON)
    endif()
endif()

if(MPSS_BUILD_MPSS_OPENSSL_STATIC AND MPSS_BUILD_MPSS_OPENSSL_SHARED)
    message(FATAL_ERROR "Cannot build both static and shared mpss-openssl libraries.")
endif()

# Check that we have at least one library to build.
if(NOT MPSS_BUILD_MPSS_CORE_STATIC
    AND NOT MPSS_BUILD_MPSS_CORE_SHARED
    AND NOT MPSS_BUILD_MPSS_OPENSSL_STATIC
    AND NOT MPSS_BUILD_MPSS_OPENSSL_SHARED)
    message(FATAL_ERROR "No library to build.")
endif()


if(MPSS_BUILD_TESTS)
    list(APPEND VCPKG_MANIFEST_FEATURES "tests")
endif()

# The provider always needs the core serializer, regardless of how the provider was enabled.
if(MPSS_BUILD_MPSS_OPENSSL_STATIC OR MPSS_BUILD_MPSS_OPENSSL_SHARED)
    if(NOT MPSS_WITH_SERIALIZATION)
        message(STATUS "[mpss] Key-reference serialization enabled by the provider.")
    endif()
    set(MPSS_WITH_SERIALIZATION ON)
    list(APPEND VCPKG_MANIFEST_FEATURES "openssl")
endif()

if(MPSS_WITH_SERIALIZATION)
    list(APPEND VCPKG_MANIFEST_FEATURES "serialization")
endif()

# Where to look for additional modules we may have.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# Enable yubikey feature in vcpkg if we are building with YubiKey backend.
if(MPSS_BACKEND_YUBIKEY)
    list(APPEND VCPKG_MANIFEST_FEATURES "yubikey")
endif()

list(REMOVE_DUPLICATES VCPKG_MANIFEST_FEATURES)

get_filename_component(mpss_TOOLCHAIN_FILENAME "${CMAKE_TOOLCHAIN_FILE}" NAME)
if(CMAKE_SYSTEM_NAME STREQUAL "Android"
    OR ANDROID
    OR DEFINED ANDROID_ABI
    OR DEFINED CMAKE_ANDROID_ARCH_ABI
    OR DEFINED CMAKE_ANDROID_NDK
    OR mpss_TOOLCHAIN_FILENAME STREQUAL "android.toolchain.cmake")
    if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
        set(ANDROID_STL c++_shared CACHE STRING "Android C++ runtime." FORCE)
        set(CMAKE_ANDROID_STL_TYPE c++_shared CACHE STRING "Android C++ runtime." FORCE)
    elseif((DEFINED ANDROID_STL AND NOT ANDROID_STL STREQUAL "c++_shared")
        OR (DEFINED CMAKE_ANDROID_STL_TYPE
            AND NOT CMAKE_ANDROID_STL_TYPE STREQUAL "c++_shared")
        OR (NOT DEFINED ANDROID_STL AND NOT DEFINED CMAKE_ANDROID_STL_TYPE))
        message(FATAL_ERROR
            "MPSS requires CMAKE_ANDROID_STL_TYPE=c++_shared on Android. "
            "Select the shared C++ runtime before enabling C++.")
    endif()
endif()

project(mpss VERSION 2.0.0 LANGUAGES C CXX)

if(MPSS_BACKEND_YUBIKEY)
    # The vcpkg port is named "yubico-piv-tool" but exports the CMake config
    # "unofficial-libykpiv" with target unofficial::libykpiv::ykpiv.
    find_package(unofficial-libykpiv CONFIG REQUIRED)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    enable_language(OBJC)
    enable_language(OBJCXX)
    enable_language(Swift)

    # Objective-C sources use automatic reference counting. Without it, a class holding an object
    # needs a hand-written dealloc to give back what its property retained, which is a rule nothing
    # checks until something leaks.
    add_compile_options($<$<COMPILE_LANGUAGE:OBJC,OBJCXX>:-fobjc-arc>)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    find_package(Java REQUIRED)
    include(UseJava)
    if(DEFINED ANDROID_PLATFORM
        AND EXISTS "${CMAKE_ANDROID_NDK}/build/cmake/adjust_api_level.cmake")
        include("${CMAKE_ANDROID_NDK}/build/cmake/adjust_api_level.cmake")
        adjust_api_level("${ANDROID_PLATFORM}" mpss_ANDROID_MIN_API)
    elseif(DEFINED ANDROID_PLATFORM)
        string(REGEX REPLACE "^android-" "" mpss_ANDROID_MIN_API "${ANDROID_PLATFORM}")
    else()
        set(mpss_ANDROID_MIN_API "${CMAKE_SYSTEM_VERSION}")
    endif()
    if(NOT mpss_ANDROID_MIN_API MATCHES "^[0-9]+$"
        OR mpss_ANDROID_MIN_API VERSION_LESS 28)
        message(FATAL_ERROR "MPSS requires Android API level 28 or later.")
    endif()
    if(NOT CMAKE_ANDROID_STL_TYPE STREQUAL "c++_shared"
        OR (DEFINED ANDROID_STL AND NOT ANDROID_STL STREQUAL "c++_shared"))
        message(FATAL_ERROR
            "MPSS requires CMAKE_ANDROID_STL_TYPE=c++_shared on Android.")
    endif()
    set(MPSS_ANDROID_COMPILE_API "36" CACHE STRING
        "Android API level used to compile the MPSS Java sources.")
    if(NOT MPSS_ANDROID_COMPILE_API MATCHES "^[0-9]+$"
        OR MPSS_ANDROID_COMPILE_API VERSION_LESS mpss_ANDROID_MIN_API)
        message(FATAL_ERROR
            "MPSS_ANDROID_COMPILE_API must be a numeric API level greater "
            "than or equal to the Android minimum API level.")
    endif()
    set(MPSS_ANDROID_BUILD_TOOLS_VERSION "${MPSS_ANDROID_COMPILE_API}.0.0"
        CACHE STRING "Android SDK Build Tools version used by the test host.")
    if(NOT MPSS_ANDROID_BUILD_TOOLS_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
        message(FATAL_ERROR
            "MPSS_ANDROID_BUILD_TOOLS_VERSION must be a numeric version.")
    endif()
endif()

# Security hardening flags. Applied as directory-scope options; do NOT
# propagate to downstream consumers via the install/export interface.
if(MPSS_ENABLE_HARDENING)
    if(MSVC)
        include(CheckCXXCompilerFlag)
        include(CheckCXXSourceCompiles)

        # Control Flow Guard.
        add_compile_options(/guard:cf)
        add_link_options(/guard:cf)

        # Spectre variant 1 mitigations.
        check_cxx_compiler_flag(/Qspectre MPSS_HAS_QSPECTRE)
        if(MPSS_HAS_QSPECTRE)
            add_compile_options(/Qspectre)
        endif()

        # These two need the compiler's own target macros: the generator platform
        # variables are not reliably set under every generator, and
        # check_linker_flag accepts any flag on MSVC, so neither can gate them.
        # Each probe states the targets it wants and fails everything else, so the
        # condition reads the same way round as the comment above it.

        # EH continuation metadata is supported for 64-bit targets, x64 and ARM64 alike.
        check_cxx_source_compiles("
            #if defined(_M_X64) || defined(_M_ARM64) || defined(_M_ARM64EC)
            int main() { return 0; }
            #else
            #error Not a 64-bit target.
            #endif
            " MPSS_MSVC_TARGET_IS_64BIT)

        if(MPSS_MSVC_TARGET_IS_64BIT)
            # Protects the exception-handling continuation targets, of which the C
            # boundary has many.
            check_cxx_compiler_flag(/guard:ehcont MPSS_HAS_GUARD_EHCONT)
            if(MPSS_HAS_GUARD_EHCONT)
                add_compile_options(/guard:ehcont)
                add_link_options(/guard:ehcont)
            endif()
        endif()

        # The shadow stack marking applies to x64 only. ARM64EC has to be excluded
        # by name because it defines _M_X64 too, being x64-compatible by design.
        check_cxx_source_compiles("
            #if defined(_M_X64) && !defined(_M_ARM64EC)
            int main() { return 0; }
            #else
            #error Not an x64 target.
            #endif
            " MPSS_MSVC_TARGET_IS_X64)

        if(MPSS_MSVC_TARGET_IS_X64)
            add_link_options(/CETCOMPAT)
        endif()

        # Do not add /DEPENDENTLOADFLAG here: it breaks loading the app-local
        # OpenSSL and libykpiv DLLs that the shared and YubiKey builds rely on.
    else()
        # Gate compile flags to clang/gcc-driven languages so they don't leak
        # into Swift's compile/link driver on Apple targets.
        set(_mpss_c_family_langs "$<COMPILE_LANGUAGE:C,CXX,OBJC,OBJCXX>")

        # Stack canaries.
        add_compile_options($<${_mpss_c_family_langs}:-fstack-protector-strong>)

        # Stack-clash protection (no-op on Apple Clang; gated for older
        # GCC/Clang versions that don't support the flag).
        if(NOT APPLE)
            include(CheckCCompilerFlag)
            check_c_compiler_flag(-fstack-clash-protection MPSS_HAS_STACK_CLASH_PROTECTION)
            if(MPSS_HAS_STACK_CLASH_PROTECTION)
                add_compile_options($<${_mpss_c_family_langs}:-fstack-clash-protection>)
            endif()
        endif()

        # Position-independent code (PIC for libraries, PIE for executables).
        set(CMAKE_POSITION_INDEPENDENT_CODE ON)

        # Standard library hardening (bounds-checked containers, etc.).
        # Gated to C-family languages for consistency with the compile-flag
        # gating above; Swift's clang importer has no use for these.
        add_compile_definitions(
            $<$<AND:$<NOT:$<CONFIG:Debug>>,${_mpss_c_family_langs}>:_GLIBCXX_ASSERTIONS>
            $<$<AND:$<NOT:$<CONFIG:Debug>>,${_mpss_c_family_langs}>:_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST>
        )

        # Full RELRO, immediate binding, non-executable stack (ELF only).
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android")
            add_link_options(-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
        endif()

        # Fortified libc functions (requires -O1+, skip on Apple).
        if(NOT APPLE)
            add_compile_options($<$<AND:$<NOT:$<CONFIG:Debug>>,${_mpss_c_family_langs}>:-U_FORTIFY_SOURCE>)
            add_compile_definitions($<$<AND:$<NOT:$<CONFIG:Debug>>,${_mpss_c_family_langs}>:_FORTIFY_SOURCE=2>)
        endif()
    endif()
endif()

# Define additional directory path variables.
include(GNUInstallDirs)

# Setup runtime path for shared/dylib `cmake --install` flows. Apple:
# loader-relative so an installed .dylib resolves siblings in the same lib
# dir or via the standard bin/ -> ../lib/ layout. ELF: absolute install lib
# dir matching the configure-time prefix. Has no effect on the iOS
# XCFramework path, which ships static archives carrying no LC_RPATH.
if(APPLE)
    set(CMAKE_INSTALL_RPATH "@loader_path;@loader_path/../${CMAKE_INSTALL_LIBDIR}")
else()
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
endif()
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)

# Define source tree variables.
set(mpss_INCLUDES_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(mpss_CONFIG_H_IN_FILENAME "${mpss_INCLUDES_DIR}/mpss/config.h.in")
set(mpss_CONFIG_IN_FILENAME "${CMAKE_CURRENT_LIST_DIR}/cmake/mpssConfig.cmake.in")

# Define build tree variables.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
set(mpss_CONFIG_H_FILENAME "${CMAKE_CURRENT_BINARY_DIR}/mpss/config.h")
set(mpss_CONFIG_FILENAME "${CMAKE_CURRENT_BINARY_DIR}/cmake/mpssConfig.cmake")
set(mpss_TARGETS_FILENAME "${CMAKE_CURRENT_BINARY_DIR}/cmake/mpssTargets.cmake")
set(mpss_CONFIG_VERSION_FILENAME "${CMAKE_CURRENT_BINARY_DIR}/cmake/mpssConfigVersion.cmake")

# Define the install directories. Headers and CMake config are unversioned;
# multiple side-by-side mpss versions on the same prefix are not supported.
set(mpss_CONFIG_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/mpss")
set(mpss_INCLUDES_INSTALL_DIR "${CMAKE_INSTALL_INCLUDEDIR}")

set(mpss_ARCHIVE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}")

# Clean config.h from the source dir when configuring.
if(EXISTS "${mpss_CONFIG_H_FILENAME}")
    message(STATUS "Cleaning up ${mpss_CONFIG_H_FILENAME}")
    file(REMOVE "${mpss_CONFIG_H_FILENAME}")
endif()

# List of all source files.
set(mpss_SOURCE_FILES "")
set(mpss_SWIFT_SOURCE_FILES "")
set(mpss_JAR_SOURCE_FILES "")

if(MPSS_BUILD_MPSS_CORE_STATIC OR MPSS_BUILD_MPSS_CORE_SHARED)
    add_subdirectory(mpss)
endif()

set(mpss_openssl_SOURCE_FILES "")

if(MPSS_BUILD_MPSS_OPENSSL_STATIC OR MPSS_BUILD_MPSS_OPENSSL_SHARED)
    add_subdirectory(mpss-openssl)
endif()

# These must be set before configure_file so they propagate into config.h.
# mpss/defines.h keys __declspec(dllexport)/(dllimport) off MPSS_CORE_IS_SHARED
# on MSVC; if it's unset at substitution time, a Windows DLL build produces
# zero exported symbols and no import library.
if(MPSS_BUILD_MPSS_CORE_SHARED)
    set(MPSS_CORE_IS_SHARED ON)
endif()
if(MPSS_BUILD_MPSS_OPENSSL_SHARED)
    set(MPSS_OPENSSL_IS_SHARED ON)
endif()

# Create config.h from config.h.in.
configure_file("${mpss_CONFIG_H_IN_FILENAME}" "${mpss_CONFIG_H_FILENAME}")

if(MPSS_BUILD_MPSS_CORE_SHARED)
    set(mpss_LIBRARY_TYPE SHARED)
elseif(MPSS_BUILD_MPSS_CORE_STATIC)
    set(mpss_LIBRARY_TYPE STATIC)
endif()

if(MPSS_BUILD_MPSS_OPENSSL_SHARED)
    set(mpss_openssl_LIBRARY_TYPE SHARED)
elseif(MPSS_BUILD_MPSS_OPENSSL_STATIC)
    set(mpss_openssl_LIBRARY_TYPE STATIC)
endif()

if(MPSS_BUILD_MPSS_CORE_STATIC OR MPSS_BUILD_MPSS_CORE_SHARED)
    if(mpss_LIBRARY_TYPE STREQUAL "STATIC")
        message(STATUS "[mpss] Building static library.")
        set(mpss_TARGET mpss_static)
        add_library(${mpss_TARGET} ${mpss_LIBRARY_TYPE} ${mpss_SOURCE_FILES})
    elseif(mpss_LIBRARY_TYPE STREQUAL "SHARED")
        message(STATUS "[mpss] Building shared library.")

        set(mpss_TARGET mpss)
        add_library(${mpss_TARGET} ${mpss_LIBRARY_TYPE} ${mpss_SOURCE_FILES})
    else()
        message(FATAL_ERROR "[mpss] Invalid value for mpss_LIBRARY_TYPE: ${mpss_LIBRARY_TYPE}")
    endif()

    # On macOS and iOS we need to build the Swift functions as well.
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
        target_sources(${mpss_TARGET} PRIVATE ${mpss_SWIFT_SOURCE_FILES})
    endif()
endif()

if(MPSS_BUILD_MPSS_OPENSSL_STATIC OR MPSS_BUILD_MPSS_OPENSSL_SHARED)
    if(mpss_openssl_LIBRARY_TYPE STREQUAL "STATIC")
        message(STATUS "[mpss-openssl] Building static library.")
        set(mpss_openssl_TARGET mpss_openssl_static)
        add_library(${mpss_openssl_TARGET} ${mpss_openssl_LIBRARY_TYPE} ${mpss_openssl_SOURCE_FILES})
    elseif(mpss_openssl_LIBRARY_TYPE STREQUAL "SHARED")
        message(STATUS "[mpss-openssl] Building shared library.")

        set(mpss_openssl_TARGET mpss_openssl)
        add_library(${mpss_openssl_TARGET} ${mpss_openssl_LIBRARY_TYPE} ${mpss_openssl_SOURCE_FILES})
    else()
        message(FATAL_ERROR "[mpss-openssl] Invalid value for mpss_openssl_LIBRARY_TYPE: ${mpss_openssl_LIBRARY_TYPE}")
    endif()
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Android")
    if(MPSS_BUILD_MPSS_CORE_STATIC OR MPSS_BUILD_MPSS_OPENSSL_STATIC)
        # Android does not support static libraries.
        message(FATAL_ERROR "Static libraries are not supported on Android.")
    endif()

    # CMAKE_SYSTEM_VERSION contains the minimum Android API level for native code.
    set(ANDROID_SDK $ENV{ANDROID_HOME})
    set(ANDROID_JAR "${ANDROID_SDK}/platforms/android-${MPSS_ANDROID_COMPILE_API}/android.jar")
    if(NOT EXISTS "${ANDROID_JAR}")
        message(WARNING "Did not find: ${ANDROID_JAR}")
        message(FATAL_ERROR
            "Android compile SDK not found. Set ANDROID_HOME and install "
            "platforms;android-${MPSS_ANDROID_COMPILE_API}.")
    endif()
    set(CMAKE_JAVA_INCLUDE_PATH "${ANDROID_JAR}")

    # Emit bytecode compatible with the modern Android build-tool baseline.
    set(CMAKE_JAVA_COMPILE_FLAGS --release 17)

    find_file(mpss_ANDROID_CXX_SHARED_LIBRARY
        NAMES libc++_shared.so
        PATHS ${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES}
        NO_DEFAULT_PATH
        REQUIRED
    )

    # Add Jar file with Java part of the code.
    add_jar(mpss_jar
        SOURCES ${mpss_JAR_SOURCE_FILES}
        OUTPUT_NAME mpss
        OUTPUT_DIR ${CMAKE_BINARY_DIR}/lib)
endif()

if(TARGET ${mpss_TARGET})
    # Require C++20 for mpss and downstream.
    target_compile_features(${mpss_TARGET} PUBLIC cxx_std_20)

    # Internally, mpss indicates a debug build with the macro MPSS_DEBUG_BUILD. This is
    # only used in the mpss source files, so it does not need to be set when compiling
    # downstream code that includes mpss headers.
    target_compile_definitions(${mpss_TARGET} PRIVATE
        $<BUILD_INTERFACE:$<$<CONFIG:Debug>:MPSS_DEBUG_BUILD>>
    )

    # Platform-specific dependencies.
    if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        # mpss on Windows requires ncrypt.lib, and tbs.lib to confirm that a machine has no TPM.
        target_link_libraries(${mpss_TARGET} PRIVATE ncrypt)
        target_link_libraries(${mpss_TARGET} PRIVATE tbs)
        target_link_libraries(${mpss_TARGET} PRIVATE crypt32)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
        target_link_libraries(${mpss_TARGET} PRIVATE
            "-framework Foundation"
            "-framework Security"
            "-framework CryptoKit")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
        # Nothing to do.
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # Linux has no OS-native backend, so there are no platform-specific
        # dependencies. YubiKey backend is supported, if enabled.
    else()
        message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}")
    endif()

    # Add backend-specific include directories and libraries. These are PUBLIC
    # so that consumers of a static mpss library can resolve the transitive
    # dependencies (e.g., libykpiv, OpenSSL) at their final link stage.
    target_link_libraries(${mpss_TARGET} PUBLIC ${mpss_LINK_LIBRARIES})

    if(MPSS_WITH_SERIALIZATION)
        find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)
        target_link_libraries(${mpss_TARGET} PRIVATE OpenSSL::Crypto)
    endif()

    # For debug builds, append "_debug" to the library names.
    set_target_properties(${mpss_TARGET} PROPERTIES DEBUG_POSTFIX "_debug")

    # Set the VERSION and SOVERSION properties for semantic versioning.
    set_target_properties(${mpss_TARGET} PROPERTIES
        VERSION ${mpss_VERSION}
        SOVERSION ${mpss_VERSION_MAJOR}
    )

    # Set our include directories.
    target_include_directories(${mpss_TARGET} PUBLIC
        $<BUILD_INTERFACE:${mpss_INCLUDES_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<INSTALL_INTERFACE:${mpss_INCLUDES_INSTALL_DIR}>
    )

    # Add our targets to an export mpssTargets.
    if(MPSS_BUILD_MPSS_CORE_STATIC)
        install(TARGETS ${mpss_TARGET} EXPORT mpssTargets
            ARCHIVE DESTINATION "${mpss_ARCHIVE_INSTALL_DIR}"
        )
    elseif(MPSS_BUILD_MPSS_CORE_SHARED)
        # This allows multiple versions for shared libraries on Linux since the
        # filenames are disambiguated by the version. On Windows, only a single
        # version can be installed at a time. On Windows, import libraries go to
        # ARCHIVE and DLLs to RUNTIME. On Linux, shared libraries go to LIBRARY.
        install(TARGETS ${mpss_TARGET} EXPORT mpssTargets
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        )

        if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
            target_compile_definitions(${mpss_TARGET} PRIVATE
                MPSS_EXPORTS
            )
        endif()
    endif()
endif()

if(TARGET ${mpss_openssl_TARGET})
    # Require C++20 and C17 for mpss-openssl. These are only internal requirements.
    target_compile_features(${mpss_openssl_TARGET} PRIVATE cxx_std_20)
    target_compile_features(${mpss_openssl_TARGET} PRIVATE c_std_17)

    target_compile_definitions(${mpss_openssl_TARGET} PRIVATE
        $<BUILD_INTERFACE:$<$<CONFIG:Debug>:MPSS_DEBUG_BUILD>>
    )

    # We also need to link against OpenSSL::Crypto. This is a public dependency.
    # The store delete dispatch (OSSL_FUNC_STORE_DELETE) requires OpenSSL 3.2.
    find_package(OpenSSL 3.2 REQUIRED)
    target_link_libraries(${mpss_openssl_TARGET} PUBLIC OpenSSL::Crypto)

    # Naturally, we depend on mpss. This is a PUBLIC dependency because
    # consumers of mpss-openssl also need to link against (and include) mpss.
    target_link_libraries(${mpss_openssl_TARGET} PUBLIC ${mpss_TARGET})

    set_target_properties(${mpss_openssl_TARGET} PROPERTIES DEBUG_POSTFIX "_debug")

    set_target_properties(${mpss_openssl_TARGET} PROPERTIES
        VERSION ${mpss_VERSION}
        SOVERSION ${mpss_VERSION_MAJOR}
    )

    # The install interface is PUBLIC so that consumers (including C projects)
    # can find the mpss-openssl headers after installation. The build interface
    # is PRIVATE to avoid exposing the entire source tree during development.
    target_include_directories(${mpss_openssl_TARGET} PUBLIC
        $<INSTALL_INTERFACE:${mpss_INCLUDES_INSTALL_DIR}>
    )
    target_include_directories(${mpss_openssl_TARGET} PRIVATE
        $<BUILD_INTERFACE:${mpss_INCLUDES_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    )

    if(MPSS_BUILD_MPSS_OPENSSL_STATIC)
        install(TARGETS ${mpss_openssl_TARGET} EXPORT mpssTargets
            ARCHIVE DESTINATION "${mpss_ARCHIVE_INSTALL_DIR}"
        )
    elseif(MPSS_BUILD_MPSS_OPENSSL_SHARED)
        install(TARGETS ${mpss_openssl_TARGET} EXPORT mpssTargets
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        )

        if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
            target_compile_definitions(${mpss_openssl_TARGET} PRIVATE
                MPSS_OPENSSL_EXPORTS
            )
        endif()
    endif()
endif()

# Create the CMake config file.
include(CMakePackageConfigHelpers)
configure_package_config_file(
    "${mpss_CONFIG_IN_FILENAME}" "${mpss_CONFIG_FILENAME}"
    INSTALL_DESTINATION "${mpss_CONFIG_INSTALL_DIR}"
    PATH_VARS mpss_INCLUDES_INSTALL_DIR
)

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    install_jar(mpss_jar DESTINATION "lib")
    install(
        FILES "${mpss_ANDROID_CXX_SHARED_LIBRARY}"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    )
endif()

install(
    EXPORT mpssTargets
    NAMESPACE mpss::
    DESTINATION "${mpss_CONFIG_INSTALL_DIR}"
)

# Create a version file.
write_basic_package_version_file(
    "${mpss_CONFIG_VERSION_FILENAME}"
    VERSION ${mpss_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Install config.h.
install(
    FILES "${mpss_CONFIG_H_FILENAME}"
    DESTINATION "${mpss_INCLUDES_INSTALL_DIR}/mpss"
)

# Install the CMake config and helper modules.
install(
    FILES "${mpss_CONFIG_FILENAME}" "${mpss_CONFIG_VERSION_FILENAME}"
    DESTINATION "${mpss_CONFIG_INSTALL_DIR}"
)

# Export mpssTargets from the build tree so it can be used without installing.
export(
    EXPORT mpssTargets
    NAMESPACE mpss::
    FILE "${mpss_TARGETS_FILENAME}"
)

# Test suite.
if(MPSS_BUILD_TESTS)
    find_package(GTest CONFIG REQUIRED)
    add_subdirectory(tests)
endif()
