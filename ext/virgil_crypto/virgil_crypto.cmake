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

cmake_minimum_required (VERSION @CMAKE_VERSION@ FATAL_ERROR)

project ("@VIRGIL_DEPENDS_PACKAGE_NAME@-depends")

include (ExternalProject)

# Configure additional CMake parameters
file (APPEND "@VIRGIL_DEPENDS_ARGS_FILE@"
    "set (ENABLE_FILE_IO ON CACHE INTERNAL \"\")\n"
    "set (ENABLE_TESTING OFF CACHE INTERNAL \"\")\n"
    "set (LIB_LOW_LEVEL_API ON CACHE INTERNAL \"\")\n"
    "set (LIB_STATIC_RUNTIME OFF CACHE INTERNAL \"\")\n"
    "set (LIB_FILE_IO ON CACHE INTERNAL \"\")\n"
    "set (BUILD_SHARED_LIBS OFF CACHE INTERNAL \"\")\n"
    "set (INSTALL_EXT_LIBS @INSTALL_EXT_LIBS@ CACHE INTERNAL \"\")\n"
    "set (INSTALL_EXT_HEADERS @INSTALL_EXT_HEADERS@ CACHE INTERNAL \"\")\n"
    "set (VIRGIL_CRYPTO_FEATURE_RNG_SEED_FILE @VIRGIL_CRYPTO_FEATURE_RNG_SEED_FILE@ CACHE INTERNAL \"\")\n"
)

ExternalProject_Add (${PROJECT_NAME}
    DOWNLOAD_DIR "@VIRGIL_DEPENDS_PACKAGE_DOWNLOAD_DIR@"
    URL "https://github.com/VirgilSecurity/virgil-crypto/archive/v2.6.1.tar.gz"
    URL_HASH SHA1=DA6214CF37B81D22EF5ABED1C4D78EED288D89DC
    PATCH_COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/patch"
            "${CMAKE_CURRENT_BINARY_DIR}/src/${PROJECT_NAME}/lib"
    PREFIX "@VIRGIL_DEPENDS_PACKAGE_BUILD_DIR@"
    CMAKE_ARGS "@VIRGIL_DEPENDS_CMAKE_ARGS@"
)

add_custom_target ("${PROJECT_NAME}-build" ALL COMMENT "Build package ${PROJECT_NAME}")
add_dependencies ("${PROJECT_NAME}-build" ${PROJECT_NAME})
