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

project (virgil_sdk CXX)

# Enable C++11
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

# Configurable variables
## Features
set (ENABLE_TESTING OFF CACHE BOOL "Enable unit tests")
set (ENABLE_EXAMPLES OFF CACHE BOOL "Enable build of Examples")
set (INSTALL_EXAMPLES OFF CACHE BOOL "Enable Examples installation")
## Installation directories
set (INSTALL_EXT_LIBS OFF CACHE BOOL "Enable installation of SDK dependency libraries")
set (INSTALL_EXT_INCLUDES OFF CACHE BOOL "Enable installation of SDK dependency library headers")
mark_as_advanced (INSTALL_EXT_LIBS INSTALL_EXT_INCLUDES)
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

# Define library name
set (VIRGIL_SDK ${CMAKE_PROJECT_NAME})

# Set library version
set (VIRGIL_SDK_VERSION_MAJOR 3)
set (VIRGIL_SDK_VERSION_MINOR 0)
set (VIRGIL_SDK_VERSION_PATCH 2)
set (VIRGIL_SDK_VERSION
    ${VIRGIL_SDK_VERSION_MAJOR}.${VIRGIL_SDK_VERSION_MINOR}.${VIRGIL_SDK_VERSION_PATCH}
)
message (STATUS "Virgil SDK version: " ${VIRGIL_SDK_VERSION})

set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

# Add self includes
include_directories ("include")

# Add external dependencies
include (ExternalProject)

include (json)
include_directories (${JSON_INCLUDE_DIRS})

include (rest)
include_directories (${REST_INCLUDE_DIRS})

include (virgil_crypto)
include_directories (${VIRGIL_CRYPTO_INCLUDE_DIRS})

find_package (CURL REQUIRED)
include_directories (${CURL_INCLUDE_DIRS})

# Grab source directory tree
file (GLOB_RECURSE SRC_LIST "src/*.cxx")
foreach (SRC_FILE ${SRC_LIST})
    string (REPLACE "${CMAKE_CURRENT_SOURCE_DIR}/src/" "" SRC_REL_PATH ${SRC_FILE})
    configure_file (
        "${CMAKE_CURRENT_SOURCE_DIR}/src/${SRC_REL_PATH}"
        "${CMAKE_CURRENT_BINARY_DIR}/src/${SRC_REL_PATH}"
        @ONLY
    )
endforeach ()
file (GLOB_RECURSE SRC_LIST "${CMAKE_CURRENT_BINARY_DIR}/src/*.cxx")

# Configure library build
add_library (${VIRGIL_SDK} STATIC ${SRC_LIST})
add_dependencies(${VIRGIL_SDK} json virgil_crypto rest)
target_link_libraries (${VIRGIL_SDK} ${VIRGIL_CRYPTO_LIBRARIES} ${REST_LIBRARIES} ${CURL_LIBRARIES})

# Install
install (TARGETS ${VIRGIL_SDK} DESTINATION lib)
if (INSTALL_EXT_LIBS)
    install (FILES ${REST_LIBRARY} DESTINATION lib)
    install (FILES ${VIRGIL_CRYPTO_LIBRARIES} DESTINATION lib)
    if (INSTALL_EXT_INCLUDES)
        install (DIRECTORY "${JSON_INCLUDE_DIRS}/" DESTINATION "include")
        install (DIRECTORY "${REST_INCLUDE_DIRS}/" DESTINATION "include")
        install (DIRECTORY "${VIRGIL_CRYPTO_INCLUDE_DIRS}/" DESTINATION "include")
    endif (INSTALL_EXT_INCLUDES)
endif (INSTALL_EXT_LIBS)

install (DIRECTORY "include/" DESTINATION "include"
     PATTERN "util" EXCLUDE
     PATTERN "endpoints" EXCLUDE
     PATTERN "ClientConnection.h" EXCLUDE
     PATTERN "Headers.h" EXCLUDE
)

# Add unit tests
if (ENABLE_TESTING)
    enable_testing()
    add_subdirectory (tests)
    message (STATUS "Unit tests status: ENABLED")
else (ENABLE_TESTING)
    message (STATUS "Unit tests status: DISABLED")
endif (ENABLE_TESTING)

# Add examples
if (ENABLE_EXAMPLES)
    add_subdirectory (examples)
    message (STATUS "Examples status: ENABLED")
else (ENABLE_EXAMPLES)
    message (STATUS "Examples status: DISABLED")
endif (ENABLE_EXAMPLES)

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
        set (DOXYGEN_EXCLUDE
            "${CMAKE_CURRENT_SOURCE_DIR}/include/virgil/sdk/util/*"
            "${CMAKE_CURRENT_SOURCE_DIR}/include/virgil/sdk/endpoints/*"
            "${CMAKE_CURRENT_SOURCE_DIR}/include/virgil/sdk/http/Headers.h"
            "${CMAKE_CURRENT_SOURCE_DIR}/include/virgil/sdk/client/ClientConnection.h"
        )
        string (REPLACE ";" " " DOXYGEN_EXCLUDE "${DOXYGEN_EXCLUDE}")
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
