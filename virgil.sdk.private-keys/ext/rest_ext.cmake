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

# Dependecy to https://github.com/anuragsoni/restless

# Define CMake variables
set (CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
    -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
    -DCMAKE_CXX_FLAGS:STRING=${CMAKE_CXX_FLAGS}
)

if (CMAKE_PREFIX_PATH)
    list (APPEND CMAKE_ARGS
        -DCMAKE_PREFIX_PATH:PATH=${CMAKE_PREFIX_PATH}
    )
endif (CMAKE_PREFIX_PATH)

# Configure external project
if (NOT TARGET project_rest)
    ExternalProject_Add (project_rest
        GIT_REPOSITORY "https://github.com/VirgilSecurity/restless.git"
        GIT_TAG "http-del-with-body"
        GIT_SUBMODULES "ext/curl"
        PREFIX "${CMAKE_CURRENT_BINARY_DIR}/rest"
        CMAKE_ARGS ${CMAKE_ARGS}
)
endif ()

# Define output
ExternalProject_Get_Property (project_rest INSTALL_DIR)

set (REST_LIBRARY_NAME ${CMAKE_STATIC_LIBRARY_PREFIX}restless${CMAKE_STATIC_LIBRARY_SUFFIX})
set (REST_INCLUDE_DIRS "${CMAKE_CURRENT_BINARY_DIR}/rest/src/project_rest/include")
set (REST_LIBRARY "${INSTALL_DIR}/bin/${REST_LIBRARY_NAME}")
set (REST_LIBRARIES "${REST_LIBRARY}" "${CURL_LIBRARIES}")

# Workaround of http://public.kitware.com/Bug/view.php?id=14495
file (MAKE_DIRECTORY ${REST_INCLUDE_DIRS})

# Make target
add_library (rest STATIC IMPORTED)
set_target_properties (rest PROPERTIES
    IMPORTED_LOCATION ${REST_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${REST_INCLUDE_DIRS}
)
add_dependencies (rest project_rest)
