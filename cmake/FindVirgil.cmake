#.rst:
# FindVirgil
# --------
#
# Find virgil
#
# Find virgil headers and libraries in the current source tree.
#
# ::
#
#   VIRGIL_INCLUDE_DIRS   - where to find virgil headers.
#   VIRGIL_LIBRARIES      - List of libraries when using virgil.
#   VIRGIL_FOUND          - True if virgil found.

#=============================================================================
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
#=============================================================================

# Look for the header files.
find_path (VIRGIL_INCLUDE_DIR NAME "virgil"
    PATHS "${CMAKE_CURRENT_SOURCE_DIR}/origin_lib/include" NO_DEFAULT_PATH
)
mark_as_advanced (VIRGIL_INCLUDE_DIR)

# Look for the library (sorted from most current/relevant entry to least).
find_library (VIRGIL_LIBRARY NAMES virgil
    PATHS "${CMAKE_CURRENT_SOURCE_DIR}/origin_lib/lib" NO_DEFAULT_PATH
)
mark_as_advanced (VIRGIL_LIBRARY)

find_library (MBEDTLS_LIBRARY NAMES mbedtls
    PATHS "${CMAKE_CURRENT_SOURCE_DIR}/origin_lib/lib" NO_DEFAULT_PATH
)
mark_as_advanced (MBEDTLS_LIBRARY)

find_library (JSONCPP_LIBRARY NAMES jsoncpp
    PATHS "${CMAKE_CURRENT_SOURCE_DIR}/origin_lib/lib" NO_DEFAULT_PATH
)
mark_as_advanced (JSONCPP_LIBRARY)

# handle the QUIETLY and REQUIRED arguments and set CURL_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args (VIRGIL REQUIRED_VARS
        VIRGIL_INCLUDE_DIR VIRGIL_LIBRARY MBEDTLS_LIBRARY JSONCPP_LIBRARY)

if (VIRGIL_FOUND)
  set (VIRGIL_LIBRARIES ${VIRGIL_LIBRARY} ${MBEDTLS_LIBRARY} ${JSONCPP_LIBRARY})
  set (VIRGIL_INCLUDE_DIRS ${VIRGIL_INCLUDE_DIR})
endif ()
