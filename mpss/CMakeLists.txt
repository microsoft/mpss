# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

# Check that this CMake file is not invoked directly.
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# Add the source files from this directory.
list(APPEND mpss_SOURCE_FILES
    "${CMAKE_CURRENT_LIST_DIR}/log.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/mpss.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/stdout_log.cpp"
)

add_subdirectory(impl)
add_subdirectory(utils)

install(
    FILES
        "${CMAKE_CURRENT_LIST_DIR}/algorithm.h"
        "${CMAKE_CURRENT_LIST_DIR}/defines.h"
        "${CMAKE_CURRENT_LIST_DIR}/interaction_handler.h"
        "${CMAKE_CURRENT_LIST_DIR}/key_info.h"
        "${CMAKE_CURRENT_LIST_DIR}/key_policy.h"
        "${CMAKE_CURRENT_LIST_DIR}/log.h"
        "${CMAKE_CURRENT_LIST_DIR}/log_c.h"
        "${CMAKE_CURRENT_LIST_DIR}/mpss.h"
        "${CMAKE_CURRENT_LIST_DIR}/secure_types.h"
    DESTINATION
        "${mpss_INCLUDES_INSTALL_DIR}/mpss"
)

# Update variables in the parent scope.
set(mpss_SOURCE_FILES ${mpss_SOURCE_FILES} PARENT_SCOPE)
set(mpss_INCLUDE_DIRS ${mpss_INCLUDE_DIRS} PARENT_SCOPE)
set(mpss_LINK_LIBRARIES ${mpss_LINK_LIBRARIES} PARENT_SCOPE)

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    set(mpss_SWIFT_SOURCE_FILES ${mpss_SWIFT_SOURCE_FILES} PARENT_SCOPE)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    set(mpss_JAR_SOURCE_FILES ${mpss_JAR_SOURCE_FILES} PARENT_SCOPE)
endif()
