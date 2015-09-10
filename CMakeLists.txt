#
# Copyright (C) 2014 Virgil Security Inc.
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
#     - VIRGIL_SDK_KEYS - boolean value that enable build of Public Keys SDK
#     - VIRGIL_SDK_PRIVATE_KEYS - boolean value that enable build of Private Keys SDK
#     - VIRGIL_EXAMPLES - boolean value that enable build of Examples
#     - ENABLE_TESTING  - boolean value that enable unit tests

cmake_minimum_required (VERSION 3.2 FATAL_ERROR)

project (virgil-cpp)

set (VIRGIL_SDK_KEYS OFF CACHE BOOL "Enable build of Public Keys SDK")
set (VIRGIL_SDK_PRIVATE_KEYS OFF CACHE BOOL "Enable build of Private Keys SDK")
set (VIRGIL_EXAMPLES OFF CACHE BOOL "Enable build of Examples")
set (ENABLE_TESTING  OFF CACHE BOOL "Enable unit tests")

if (ENABLE_TESTING)
    enable_testing ()
endif (ENABLE_TESTING)

if (VIRGIL_SDK_KEYS)
    add_subdirectory (virgil.sdk.keys)
endif (VIRGIL_SDK_KEYS)

if (VIRGIL_SDK_PRIVATE_KEYS)
    add_subdirectory (virgil.sdk.private-keys)
endif (VIRGIL_SDK_PRIVATE_KEYS)

if (VIRGIL_EXAMPLES)
    add_subdirectory (examples)
endif (VIRGIL_EXAMPLES)
