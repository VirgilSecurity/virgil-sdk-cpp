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

set (CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
    -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}
    -DLIB_LOW_LEVEL_API:BOOL=ON
    -DLIB_FILE_IO:BOOL=ON
    -DENABLE_TESTING:BOOL=OFF
)

list (APPEND CMAKE_ARGS
    -DCMAKE_CXX_COMPILER:STRING=${CMAKE_CXX_COMPILER}
    -DCMAKE_CXX_FLAGS:STRING=${CMAKE_CXX_FLAGS}
    -DCMAKE_CXX_FLAGS_RELEASE:STRING=${CMAKE_CXX_FLAGS_RELEASE}
    -DCMAKE_CXX_FLAGS_DEBUG:STRING=${CMAKE_CXX_FLAGS_DEBUG}
)

if (CMAKE_PREFIX_PATH)
    list (APPEND CMAKE_ARGS
        -DCMAKE_PREFIX_PATH:PATH=${CMAKE_PREFIX_PATH}
    )
endif (CMAKE_PREFIX_PATH)

if (NOT TARGET virgil_crypto_project)
    ExternalProject_Add (virgil_crypto_project
        GIT_REPOSITORY "https://github.com/VirgilSecurity/virgil-crypto.git"
        GIT_TAG "v1.3.4"
        PREFIX "${CMAKE_BINARY_DIR}/ext/virgil-crypto"
        CMAKE_ARGS ${CMAKE_ARGS}
    )
endif ()

if (NOT TARGET virgil_crypto)
    # Payload targets and output variables
    ExternalProject_Get_Property (virgil_crypto_project INSTALL_DIR)

    set (VIRGIL_CRYPTO_LIBRARY_NAME ${CMAKE_STATIC_LIBRARY_PREFIX}virgil_crypto${CMAKE_STATIC_LIBRARY_SUFFIX})
    set (MBEDTLS_LIBRARY_NAME ${CMAKE_STATIC_LIBRARY_PREFIX}mbedcrypto${CMAKE_STATIC_LIBRARY_SUFFIX})
    set (VIRGIL_CRYPTO_INCLUDE_DIRS "${INSTALL_DIR}/include")
    set (VIRGIL_CRYPTO_LIBRARIES
            "${INSTALL_DIR}/lib/${VIRGIL_CRYPTO_LIBRARY_NAME};${INSTALL_DIR}/lib/${MBEDTLS_LIBRARY_NAME}")

    # Workaround of http://public.kitware.com/Bug/view.php?id=14495
    file (MAKE_DIRECTORY ${VIRGIL_CRYPTO_INCLUDE_DIRS})

    add_library (virgil_crypto STATIC IMPORTED GLOBAL)
    set_property (TARGET virgil_crypto PROPERTY IMPORTED_LOCATION ${VIRGIL_LIBRARY})
    set_property (TARGET virgil_crypto PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${VIRGIL_CRYPTO_INCLUDE_DIRS})
    set_property (TARGET virgil_crypto PROPERTY INTERFACE_LINK_LIBRARIES "${INSTALL_DIR}/lib/${MBEDTLS_LIBRARY_NAME}")
    add_dependencies (virgil_crypto virgil_crypto_project)
endif ()
