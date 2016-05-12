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

# Configurable variables:
#     - INSTALL_BIN_DIR_NAME  - name of the directory where binaries will be installed.
#     - INSTALL_MAN_DIR_NAME  - name of the directory where man pages will be installed.
#     - INSTALL_DOC_DIR_NAME  - name of the directory where documentation will be installed.
#
# Define variables:
#     - SIMPLE_CHAT_VERSION       - SIMPLE_CHAT full version.
#     - SIMPLE_CHAT_VERSION_MAJOR - SIMPLE_CHAT major version number.
#     - SIMPLE_CHAT_VERSION_MINOR - SIMPLE_CHAT minor version number.
#     - SIMPLE_CHAT_VERSION_PATCH - SIMPLE_CHAT patch number.

cmake_minimum_required (VERSION 3.2 FATAL_ERROR)

project (simple_chat)

# Configure path to custom modules
set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/utils" ${CMAKE_MODULE_PATH})

# Define enviroment parameters
if (CMAKE_SIZEOF_VOID_P)
    message (STATUS "Compiler pointer size: " ${CMAKE_SIZEOF_VOID_P} " bytes")
else ()
    message (STATUS "Compiler pointer size: UNDEFINED")
endif ()

# Enable C++11
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

# Inspect system
set (SYSTEM_ARCH x86)
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set (SYSTEM_ARCH x64)
endif ()
string (TOLOWER "${CMAKE_SYSTEM_NAME}" SYSTEM_NAME)

# Check compiler version
if (MSVC)
    # MSVC14
    if (NOT MSVC_VERSION EQUAL 1900)
        message (FATAL_ERROR "Unsupported MSVC version found. Allowed versions: Visual Studio 2015 (MSVC14)")
    endif (NOT MSVC_VERSION EQUAL 1900)
endif (MSVC)

# Configure path to local libraries
if (MSVC)
    set (EXT_PREBUILD_MSVC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ext/prebuild/msvc")
    set (CMAKE_PREFIX_PATH "${EXT_PREBUILD_MSVC_DIR}/${SYSTEM_ARCH}/libcurl" ${CMAKE_PREFIX_PATH})
    set (CURL_LIBRARY_DLL "${EXT_PREBUILD_MSVC_DIR}/${SYSTEM_ARCH}/libcurl/lib/libcurl.dll")
endif (MSVC)

# Configure version
set (SIMPLE_CHAT_VERSION_MAJOR 2)
set (SIMPLE_CHAT_VERSION_MINOR 0)
set (SIMPLE_CHAT_VERSION_PATCH 0)
set (SIMPLE_CHAT_VERSION ${SIMPLE_CHAT_VERSION_MAJOR}.${SIMPLE_CHAT_VERSION_MINOR}.${SIMPLE_CHAT_VERSION_PATCH})
message (STATUS "SIMPLE_CHAT version: " ${SIMPLE_CHAT_VERSION})

# Configure path variables
set (INSTALL_BIN_DIR_NAME bin CACHE STRING "Installation directory name for executables")
set (INSTALL_MAN_DIR_NAME "share/man" CACHE STRING "Installation directory name for man pages")

set(TOKEN "eyJpZCI6IjFmM2RhZThlLWI0NzItNDE3OC04ZTFlLTEyMDgwOTQ2MDMzNSIsImFwcGxpY2F0aW9uX2NhcmRfaWQiOiIyYzc0ZGRmNS0zZTcwLTQ1NmItYTE4Ny0yZTQwYWVmY2M5ODYiLCJ0dGwiOi0xLCJjdGwiOi0xLCJwcm9sb25nIjowfQ==.MIGaMA0GCWCGSAFlAwQCAgUABIGIMIGFAkB2sKGsBde6nVwfCN3XxJtOGltekVYwpcfZW2TN4VkKsgr3p7wpFZeF2Wy6P8gk11NnAIwvAAWE1wf6/vrUQzBUAkEAgkOE3Vou9U+YXI+cK2h+xG9O7ZWaKRdZa1c0RwVwCQqYQrNhz+Ct17c13g5mxcYu/FWGUxsLENZZv+6T6My2Aw==")


# Configure application token
set (VIRGIL_ACCESS_TOKEN ${TOKEN} CACHE STRING
        "Application specific token acquired from the Virgil Security")

if (NOT VIRGIL_ACCESS_TOKEN)
    message (FATAL_ERROR "VIRGIL_ACCESS_TOKEN configuration is not defined.")
endif ()

# Add system external dependencies
find_package (CURL REQUIRED)
include_directories (${CURL_INCLUDE_DIRS})

# Add in-house external dependencies
include (virgil_depends)

virgil_depends (
    PACKAGE_NAME "virgil_sdk"
    CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ext/virgil_sdk"
)

virgil_find_package (virgil_sdk 3.2.0 EXACT)
virgil_find_package (restless)      # Installed as virgil_sdk dependency, so found version will be appropriate
virgil_find_package (virgil_crypto) # Installed as virgil_sdk dependency, so found version will be appropriate
virgil_find_package (MbedTLS)       # Installed as virgil_sdk dependency, so found version will be appropriate

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

add_executable (simple_chat ${SRC_LIST})
target_include_directories (${PROJECT_NAME}
    PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
)
target_link_libraries (simple_chat virgil::security::virgil_sdk ${CURL_LIBRARIES})

# Install simple_chat
install (TARGETS simple_chat DESTINATION ${INSTALL_BIN_DIR_NAME})

if (MSVC)
    install (PROGRAMS "${CURL_LIBRARY_DLL}" DESTINATION "${INSTALL_BIN_DIR_NAME}")
    install (PROGRAMS "${EXT_PREBUILD_MSVC_DIR}/install/vc_redist.${SYSTEM_ARCH}.exe" DESTINATION "install")
endif (MSVC)
