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
set (ENABLE_TESTING ON CACHE BOOL "Enable unit tests")
set (VIRGIL_EXAMPLES ON CACHE BOOL "Enable build of Examples")

# Define library name
set (VIRGIL_SDK_NAME ${CMAKE_PROJECT_NAME})

# Set library version
set (VIRGIL_SDK_VERSION_MAJOR 1)
set (VIRGIL_SDK_VERSION_MINOR 0)
set (VIRGIL_SDK_VERSION_PATCH 0)
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

include (virgil)
virgil_add_dependency ("crypto"
    VIRGIL_CRYPTO_DEPENDENCIES
    VIRGIL_CRYPTO_INCLUDE_DIRS
    VIRGIL_CRYPTO_LIBRARIES
)
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
add_library (${VIRGIL_SDK_NAME} STATIC ${SRC_LIST})
target_link_libraries (${VIRGIL_SDK_NAME} rest ${VIRGIL_CRYPTO_LIBRARIES} ${CURL_LIBRARIES})
add_dependencies (${VIRGIL_SDK_NAME} json)

# Install
install (TARGETS ${VIRGIL_SDK_NAME} DESTINATION lib)
install (FILES ${REST_LIBRARY} DESTINATION lib)
install (DIRECTORY "include/" DESTINATION "include" PATTERN "util" EXCLUDE)

# Add unit tests
if (ENABLE_TESTING)
    enable_testing()
    add_subdirectory (tests)
    message (STATUS "Unit tests status: ENABLED")
else (ENABLE_TESTING)
    message (STATUS "Unit tests status: DISABLED")
endif (ENABLE_TESTING)

# Add examples
if (VIRGIL_EXAMPLES)
    add_subdirectory (examples)
    message (STATUS "Examples status: ENABLED")
else (VIRGIL_EXAMPLES)
    message (STATUS "Examples status: DISABLED")
endif (VIRGIL_EXAMPLES)

# Add a target to generate API documentation with Doxygen
find_package(Doxygen)

find_program(dot DOT_PROGRAM)
if (DOT_PROGRAM)
    set (DOT_FOUND "YES")
else ()
    set (DOT_FOUND "NO")
endif (DOT_PROGRAM)

if (DOXYGEN_FOUND)
    configure_file (${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target ("doc-sdk"
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/docs
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
endif (DOXYGEN_FOUND)
