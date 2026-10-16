# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

if(NOT CMAKE_SYSTEM_NAME STREQUAL "iOS")
    message(FATAL_ERROR "The iOS test host can only be built for iOS.")
endif()
if(NOT CMAKE_GENERATOR STREQUAL "Xcode")
    message(FATAL_ERROR "The iOS test host requires the Xcode generator.")
endif()
if(NOT TARGET ${mpss_TARGET})
    message(FATAL_ERROR "The iOS test host requires the MPSS core target.")
endif()
find_package(XCTest REQUIRED)

set(MPSS_IOS_TEST_BUNDLE_IDENTIFIER "com.microsoft.mpss.tests"
    CACHE STRING "Bundle identifier for the hosted iOS test application")
if(MPSS_IOS_TEST_BUNDLE_IDENTIFIER STREQUAL "")
    message(FATAL_ERROR "MPSS_IOS_TEST_BUNDLE_IDENTIFIER must not be empty.")
endif()

set(mpss_IOS_TEST_HOST mpss_ios_test_host)
set(mpss_IOS_XCTEST_TARGET mpss_ios_xctest)
set(mpss_IOS_XCTEST_BUNDLE_IDENTIFIER
    "${MPSS_IOS_TEST_BUNDLE_IDENTIFIER}.xctest")

add_executable(${mpss_IOS_TEST_HOST} MACOSX_BUNDLE
    main.m
)
set_target_properties(${mpss_IOS_TEST_HOST} PROPERTIES
    MACOSX_BUNDLE_BUNDLE_NAME "MPSS iOS Tests"
    MACOSX_BUNDLE_GUI_IDENTIFIER "${MPSS_IOS_TEST_BUNDLE_IDENTIFIER}"
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_LIST_DIR}/Info.plist.in"
    XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS
        "${CMAKE_CURRENT_LIST_DIR}/mpss_ios_test_host.entitlements"
    XCODE_ATTRIBUTE_INFOPLIST_KEY_UIApplicationSceneManifest_Generation YES
    XCODE_ATTRIBUTE_INFOPLIST_KEY_UILaunchScreen_Generation YES
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER
        "${MPSS_IOS_TEST_BUNDLE_IDENTIFIER}"
    XCODE_GENERATE_SCHEME YES
)
target_link_libraries(${mpss_IOS_TEST_HOST} PRIVATE
    "-framework UIKit"
)

add_library(mpss_ios_tests OBJECT
    ${mpss_TESTS_FILES}
)
target_link_libraries(mpss_ios_tests PRIVATE
    ${mpss_TESTS_LINK_LIBRARIES}
)

xctest_add_bundle(${mpss_IOS_XCTEST_TARGET} ${mpss_IOS_TEST_HOST}
    mpss_xctest.mm
    $<TARGET_OBJECTS:mpss_ios_tests>
)
set_target_properties(${mpss_IOS_XCTEST_TARGET} PROPERTIES
    XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED YES
    XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED NO
    XCODE_ATTRIBUTE_GENERATE_INFOPLIST_FILE YES
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER
        "${mpss_IOS_XCTEST_BUNDLE_IDENTIFIER}"
)
target_link_libraries(${mpss_IOS_XCTEST_TARGET} PRIVATE
    ${mpss_TESTS_LINK_LIBRARIES}
)
