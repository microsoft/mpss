# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(FATAL_ERROR "The Android test host can only be built for Android.")
endif()
if(NOT TARGET ${mpss_TARGET})
    message(FATAL_ERROR "The Android test host requires the MPSS core target.")
endif()
if(NOT TARGET mpss_jar)
    message(FATAL_ERROR "The Android test host requires the MPSS Java library.")
endif()

# The APK carries only shared libraries; static ones are linked into mpss_tests.
function(mpss_android_test_append_if_shared target)
    get_target_property(type ${target} TYPE)
    get_target_property(location ${target} IMPORTED_LOCATION)
    if(type STREQUAL "SHARED_LIBRARY"
        OR (type STREQUAL "UNKNOWN_LIBRARY" AND location AND NOT location MATCHES "\\.a$"))
        list(APPEND mpss_ANDROID_TEST_NATIVE_FILES "$<TARGET_FILE:${target}>")
        set(mpss_ANDROID_TEST_NATIVE_FILES ${mpss_ANDROID_TEST_NATIVE_FILES} PARENT_SCOPE)
    endif()
endfunction()

add_library(mpss_tests SHARED
    ${mpss_TESTS_FILES}
    android_tests.cpp
    test_runner.cpp
)
target_link_libraries(mpss_tests PRIVATE
    ${mpss_TESTS_LINK_LIBRARIES}
    log
)

if(CMAKE_CONFIGURATION_TYPES)
    set(mpss_ANDROID_TEST_DIRECTORY
        "${CMAKE_BINARY_DIR}/android-tests/$<CONFIG>")
else()
    set(mpss_ANDROID_TEST_DIRECTORY
        "${CMAKE_BINARY_DIR}/android-tests")
endif()
set(mpss_ANDROID_TEST_JNI_DIRECTORY
    "${mpss_ANDROID_TEST_DIRECTORY}/jniLibs/${CMAKE_ANDROID_ARCH_ABI}")
set(mpss_ANDROID_TEST_APK
    "${mpss_ANDROID_TEST_DIRECTORY}/mpss-tests.apk")
set(mpss_ANDROID_TEST_NATIVE_FILES "$<TARGET_FILE:mpss_tests>")
mpss_android_test_append_if_shared(${mpss_TARGET})
if(TARGET OpenSSL::Crypto)
    mpss_android_test_append_if_shared(OpenSSL::Crypto)
endif()
if(CMAKE_ANDROID_STL_TYPE STREQUAL "c++_shared")
    find_file(mpss_ANDROID_CXX_SHARED_LIBRARY
        NAMES libc++_shared.so
        PATHS ${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES}
        NO_DEFAULT_PATH
        REQUIRED
    )
    list(APPEND mpss_ANDROID_TEST_NATIVE_FILES "${mpss_ANDROID_CXX_SHARED_LIBRARY}")
endif()
set(mpss_ANDROID_TEST_TARGETS
    mpss_tests
    mpss_jar
    ${mpss_TARGET}
)
get_target_property(mpss_ANDROID_TEST_JAR mpss_jar JAR_FILE)

if(CMAKE_HOST_WIN32)
    set(mpss_ANDROID_TEST_GRADLEW "${CMAKE_CURRENT_LIST_DIR}/gradlew.bat")
else()
    set(mpss_ANDROID_TEST_GRADLEW "${CMAKE_CURRENT_LIST_DIR}/gradlew")
endif()
set(mpss_ANDROID_TEST_GRADLE_FILES
    "${CMAKE_CURRENT_LIST_DIR}/settings.gradle"
    "${CMAKE_CURRENT_LIST_DIR}/build.gradle"
    "${CMAKE_CURRENT_LIST_DIR}/app/build.gradle"
    "${CMAKE_CURRENT_LIST_DIR}/app/src/main/AndroidManifest.xml"
    "${CMAKE_CURRENT_LIST_DIR}/app/src/main/java/com/microsoft/mpss/tests/DirectKeyStore.java"
    "${CMAKE_CURRENT_LIST_DIR}/app/src/main/java/com/microsoft/mpss/tests/TestRunner.java"
    "${mpss_ANDROID_TEST_GRADLEW}"
    "${CMAKE_CURRENT_LIST_DIR}/gradle/wrapper/gradle-wrapper.jar"
    "${CMAKE_CURRENT_LIST_DIR}/gradle/wrapper/gradle-wrapper.properties"
)

if(TARGET ${mpss_openssl_TARGET})
    mpss_android_test_append_if_shared(${mpss_openssl_TARGET})
    mpss_android_test_append_if_shared(OpenSSL::SSL)
    list(APPEND mpss_ANDROID_TEST_TARGETS ${mpss_openssl_TARGET})
endif()

add_custom_command(
    OUTPUT "${mpss_ANDROID_TEST_APK}"
    COMMAND ${CMAKE_COMMAND} -E rm -rf
        "${mpss_ANDROID_TEST_DIRECTORY}/jniLibs"
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "${mpss_ANDROID_TEST_JNI_DIRECTORY}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${mpss_ANDROID_TEST_NATIVE_FILES}
        "${mpss_ANDROID_TEST_JNI_DIRECTORY}"
    COMMAND "${mpss_ANDROID_TEST_GRADLEW}"
        --no-daemon
        --project-cache-dir
        "${mpss_ANDROID_TEST_DIRECTORY}/gradle-cache"
        "-PmpssBuildDir=${CMAKE_BINARY_DIR}"
        "-PmpssTestDir=${mpss_ANDROID_TEST_DIRECTORY}"
        "-PmpssCompileApi=${MPSS_ANDROID_COMPILE_API}"
        "-PmpssBuildToolsVersion=${MPSS_ANDROID_BUILD_TOOLS_VERSION}"
        "-PmpssMinApi=${mpss_ANDROID_MIN_API}"
        :app:assembleDebug
    COMMAND ${CMAKE_COMMAND} -E copy
        "${mpss_ANDROID_TEST_DIRECTORY}/gradle-build/outputs/apk/debug/app-debug.apk"
        "${mpss_ANDROID_TEST_APK}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}"
    DEPENDS
        ${mpss_ANDROID_TEST_TARGETS}
        ${mpss_ANDROID_TEST_NATIVE_FILES}
        "${mpss_ANDROID_TEST_JAR}"
        ${mpss_ANDROID_TEST_GRADLE_FILES}
    COMMENT "Building Android test APK"
    USES_TERMINAL
    VERBATIM
)

add_custom_target(mpss_android_test_apk ALL
    DEPENDS "${mpss_ANDROID_TEST_APK}"
)
