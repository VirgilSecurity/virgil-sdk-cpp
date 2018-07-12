#
# Copyright (C) 2015 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

cmake_minimum_required (VERSION 3.2 FATAL_ERROR)

project (virgil_sdk VERSION 3.2.3 LANGUAGES CXX)

# Enable C++11
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

# Configurable variables
## Features
set (ENABLE_TESTING OFF CACHE BOOL "Enable unit tests")
set (ENABLE_EXAMPLES OFF CACHE BOOL "Enable build of Examples")
set (INSTALL_EXAMPLES OFF CACHE BOOL "Enable Examples installation")

## Crosscompiling
set (UCLIBC OFF CACHE BOOL "Enable pathches if SDK is build with uClibc++")

## Installation directories
set (INSTALL_INC_DIR_NAME include CACHE STRING "Installation directory name for includes")
set (INSTALL_LIB_DIR_NAME lib CACHE STRING "Installation directory name for libraries")
set (INSTALL_BIN_DIR_NAME bin CACHE STRING "Installation directory name for executables")
set (INSTALL_CFG_DIR_NAME
    "${INSTALL_LIB_DIR_NAME}/cmake/${PROJECT_NAME}" CACHE STRING
    "Path to the CMake configuration files be installed"
)

## Installation options
set (INSTALL_EXT_LIBS ON CACHE BOOL "Enable installation of SDK dependency libraries")
set (INSTALL_EXT_HEADERS OFF CACHE BOOL "Enable installation of SDK dependency library headers")
set (VIRGIL_CRYPTO_FEATURE_RNG_SEED_FILE ON CACHE BOOL "Defines whether class VirgilRandom will use additional seed from a file.")
mark_as_advanced (INSTALL_EXT_LIBS INSTALL_EXT_HEADERS)

# Build shared library if defined
set (BUILD_SHARED_LIBS OFF CACHE BOOL "Force to create shared libraries")

## Doxygen
set (DOXYGEN_EXCLUDE_PRIVATE ON CACHE BOOL "Exclude SDK private API from Doxygen documentation")
mark_as_advanced (DOXYGEN_EXCLUDE_PRIVATE)

## Environment
set (ENABLE_STAGING_ENV OFF CACHE BOOL "Use staging environment")
if (ENABLE_STAGING_ENV)
    set (VIRGIL_IDENTITY_SERVICE_URI "https://identity-stg.virgilsecurity.com"
            CACHE STRING "Base URI to the Virgil Identity service")

    set (VIRGIL_KEYS_SERVICE_URI "https://keys-stg.virgilsecurity.com"
            CACHE STRING  "Base URI to Virgil Keys service")

    set (VIRGIL_PRIVATE_KEYS_SERVICE_URI "https://keys-private-stg.virgilsecurity.com"
        CACHE STRING "Base URI to Virgil Private Keys service")
endif ()
mark_as_advanced (
    ENABLE_STAGING_ENV
    VIRGIL_IDENTITY_SERVICE_URI
    VIRGIL_KEYS_SERVICE_URI
    VIRGIL_PRIVATE_KEYS_SERVICE_URI
)

if (VIRGIL_IDENTITY_SERVICE_URI)
    add_definitions (-DVIRGIL_IDENTITY_SERVICE_URI="${VIRGIL_IDENTITY_SERVICE_URI}")
endif ()

if (VIRGIL_KEYS_SERVICE_URI)
    add_definitions (-DVIRGIL_KEYS_SERVICE_URI="${VIRGIL_KEYS_SERVICE_URI}")
endif ()

if (VIRGIL_PRIVATE_KEYS_SERVICE_URI)
    add_definitions (-DVIRGIL_PRIVATE_KEYS_SERVICE_URI="${VIRGIL_PRIVATE_KEYS_SERVICE_URI}")
endif ()

# Set library version
message (STATUS "Virgil SDK version: " ${${PROJECT_NAME}_VERSION})

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/utils" ${CMAKE_MODULE_PATH})

# Add system external dependencies
find_package (CURL REQUIRED)

# Add in-house external dependencies
include (virgil_depends)

virgil_depends (
    PACKAGE_NAME "virgil_crypto"
    CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ext/virgil_crypto"
)

virgil_depends (
    PACKAGE_NAME "nlohman_json"
    CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ext/nlohman_json"
)

virgil_depends (
    PACKAGE_NAME "restless"
    CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ext/restless"
)

virgil_find_package (virgil_crypto 2.5.0)
virgil_find_package (nlohman_json 1.1.0 EXACT)
virgil_find_package (restless 0.3.0 EXACT)
virgil_find_package (MbedTLS) # Installed as virgil_crypto dependency, so found version will be appropriate
virgil_find_package (RapidJSON) # Installed as virgil_crypto dependency, so found version will be appropriate

include_directories (${CURL_INCLUDE_DIRS})
include_directories (${NLOHMAN_JSON_INCLUDE_DIRS})

# Grab source directory tree
file (GLOB_RECURSE SRC_CONF "src/*.cxx.in")
foreach (SRC_FILE ${SRC_CONF})
    string (REPLACE "${CMAKE_CURRENT_SOURCE_DIR}/src/" "" SRC_REL_PATH ${SRC_FILE})
    string (REPLACE ".in" "" SRC_REL_PATH ${SRC_REL_PATH})
    configure_file (
        "${CMAKE_CURRENT_SOURCE_DIR}/src/${SRC_REL_PATH}.in"
        "${CMAKE_CURRENT_BINARY_DIR}/src/${SRC_REL_PATH}"
        @ONLY
    )
endforeach ()
file (GLOB_RECURSE SRC_LIST_BIN "${CMAKE_CURRENT_BINARY_DIR}/src/*.cxx")
file (GLOB_RECURSE SRC_LIST_SRC "src/*.cxx")
set (SRC_LIST ${SRC_LIST_BIN} ${SRC_LIST_SRC})

# Configure library build
add_library (${PROJECT_NAME} ${SRC_LIST})
target_include_directories (${PROJECT_NAME}
    PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
)
target_link_libraries (${PROJECT_NAME} virgil::security::virgil_crypto asoni::restless ${CURL_LIBRARIES})
target_compile_definitions (${PROJECT_NAME} PUBLIC "UCLIBC=$<BOOL:${UCLIBC}>")
set_target_properties (${PROJECT_NAME} PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    INTERFACE_POSITION_INDEPENDENT_CODE ON
    DEBUG_POSTFIX "_d"
)

if (BUILD_SHARED_LIBS)
    set_target_properties (${PROJECT_NAME} PROPERTIES
        VERSION ${${PROJECT_NAME}_VERSION} SOVERSION ${${PROJECT_NAME}_VERSION_MAJOR}
    )
endif ()

# Define names for configuration files
set (generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")
set (version_config "${generated_dir}/${PROJECT_NAME}-config-version.cmake")
set (project_config "${generated_dir}/${PROJECT_NAME}-config.cmake")
set (targets_export_name "${PROJECT_NAME}-targets")
set (namespace "virgil::security::")

# Create configuration files
include (CMakePackageConfigHelpers)

# Write Version Config
write_basic_package_version_file (
    "${version_config}" COMPATIBILITY SameMajorVersion
)

# Write Project Config
configure_package_config_file (
    "cmake/config/config.cmake.in"
    "${project_config}"
    INSTALL_DESTINATION "${INSTALL_CFG_DIR_NAME}"
)

# Install targets
install (TARGETS ${PROJECT_NAME}
    EXPORT "${targets_export_name}"
    LIBRARY DESTINATION "${INSTALL_LIB_DIR_NAME}"
    ARCHIVE DESTINATION "${INSTALL_LIB_DIR_NAME}"
    RUNTIME DESTINATION "${INSTALL_BIN_DIR_NAME}"
    INCLUDES DESTINATION "${INSTALL_INC_DIR_NAME}"
)

if (INSTALL_EXT_LIBS)
    install (DIRECTORY "${VIRGIL_DEPENDS_PREFIX}/lib/" DESTINATION "${INSTALL_LIB_DIR_NAME}")
endif (INSTALL_EXT_LIBS)

# Install headers
install (DIRECTORY "include/" DESTINATION "include"
     PATTERN "endpoints" EXCLUDE
     PATTERN "ClientConnection.h" EXCLUDE
     PATTERN "Headers.h" EXCLUDE
     PATTERN "JsonKey.h" EXCLUDE
     PATTERN "Memory.h" EXCLUDE
)

if (INSTALL_EXT_HEADERS)
    install (DIRECTORY "${VIRGIL_DEPENDS_PREFIX}/include/" DESTINATION "${INSTALL_INC_DIR_NAME}")
endif ()

# Install configurations
install (
    FILES "${project_config}" "${version_config}"
    DESTINATION "${INSTALL_CFG_DIR_NAME}"
)

install (
    EXPORT "${targets_export_name}"
    NAMESPACE "${namespace}"
    DESTINATION "${INSTALL_CFG_DIR_NAME}"
)

# Add unit tests
if (ENABLE_TESTING)
    enable_testing()
    add_subdirectory (tests)
    message (STATUS "Unit tests status: ENABLED")
else (ENABLE_TESTING)
    message (STATUS "Unit tests status: DISABLED")
endif (ENABLE_TESTING)

# Add a target to generate API documentation with Doxygen
find_package(Doxygen)

find_program(DOT_PROGRAM NAMES dot)
if (DOT_PROGRAM)
    set (DOT_FOUND "YES")
else ()
    set (DOT_FOUND "NO")
endif (DOT_PROGRAM)

if (DOXYGEN_FOUND)
    if (DOXYGEN_EXCLUDE_PRIVATE)
        set (DOXYGEN_EXTRACT_PRIVATE "NO")
    else ()
        set (DOXYGEN_EXTRACT_PRIVATE "YES")
    endif (DOXYGEN_EXCLUDE_PRIVATE)
    configure_file (${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target ("doc"
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/docs
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
endif (DOXYGEN_FOUND)

# Add a target to format code with clang-format
if (UNIX)
    find_program(CLANG_FORMAT NAMES "clang-format")
    if (CLANG_FORMAT)
        add_custom_target ("format"
            "${CMAKE_SOURCE_DIR}/utils/format_code.sh"
            COMMENT "Format code" VERBATIM
        )
    endif (CLANG_FORMAT)
endif (UNIX)
