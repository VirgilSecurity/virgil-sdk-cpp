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

cmake_minimum_required (VERSION 2.8 FATAL_ERROR)

project (keys CXX)

# Enable C++11
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

# Configurable variables
set (VIRGIL_SDK_KEYS_LIBRARY_NAME "virgil_sdk_keys" CACHE STRING "Virgil Keys SDK library name.")

# Set library version
set (VIRGIL_SDK_KEYS_VERSION_MAJOR 1)
set (VIRGIL_SDK_KEYS_VERSION_MINOR 0)
set (VIRGIL_SDK_KEYS_VERSION_PATCH 0)
set (VIRGIL_SDK_KEYS_VERSION
    ${VIRGIL_SDK_KEYS_VERSION_MAJOR}.${VIRGIL_SDK_KEYS_VERSION_MINOR}.${VIRGIL_SDK_KEYS_VERSION_PATCH}
)
message (STATUS "Virgil Keys SDK version: " ${VIRGIL_SDK_KEYS_VERSION})

# Add self includes
include_directories ("include")

# Add external dependencies
include (ExternalProject)

include ("ext/json_ext.cmake")
include_directories (${JSON_INCLUDE_DIRS})

include ("ext/rest_ext.cmake")
include_directories (${REST_INCLUDE_DIRS})

find_library (CURL_LIB curl)
if (CURL_LIB)
    message (STATUS "Found CURL: ${CURL_LIB}")
else ()
    message (FATAL_ERROR "cURL dependency library is not found in the system.")
endif ()

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
add_library (keys STATIC ${SRC_LIST})
target_link_libraries (keys rest ${CURL_LIB})
add_dependencies (keys json)
set_target_properties (keys PROPERTIES OUTPUT_NAME ${VIRGIL_SDK_KEYS_LIBRARY_NAME})

# Install
install (TARGETS keys DESTINATION lib)
install (FILES ${REST_LIBRARY} DESTINATION lib)
install (DIRECTORY "include/" DESTINATION "include" PATTERN "util" EXCLUDE)

# Add unit tests
enable_testing ()
add_subdirectory (tests)

# Add a target to generate API documentation with Doxygen
find_package(Doxygen)

find_program(dot DOT_PROGRAM)
if (DOT_PROGRAM)
    set (DOT_FOUND "YES")
else ()
    set (DOT_FOUND "NO")
endif (DOT_PROGRAM)

if(DOXYGEN_FOUND)
    configure_file (${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target (doc
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/docs
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
endif (DOXYGEN_FOUND)
