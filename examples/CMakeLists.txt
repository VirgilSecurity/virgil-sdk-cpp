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

project (virgil-sdk-examples)

file (GLOB_RECURSE DATA_FILES "${CMAKE_CURRENT_SOURCE_DIR}/data/*")

foreach (DATA_FILE ${DATA_FILES})
    string (REPLACE "${CMAKE_CURRENT_SOURCE_DIR}/data/" "" DATA_FILE_NAME ${DATA_FILE})
    configure_file (
        ${CMAKE_CURRENT_SOURCE_DIR}/data/${DATA_FILE_NAME}
        ${CMAKE_CURRENT_BINARY_DIR}/${DATA_FILE_NAME}
        COPYONLY
    )
endforeach (DATA_FILE)

aux_source_directory ("src" EXAMPLES_SRC_LIST)
foreach (SRC ${EXAMPLES_SRC_LIST})
    get_filename_component (TARGET_NAME ${SRC} NAME_WE)
    add_executable (${TARGET_NAME} ${SRC})
    target_link_libraries (${TARGET_NAME} virgil_sdk)
    if (INSTALL_EXAMPLES)
        install (TARGETS ${TARGET_NAME} DESTINATION "share/doc/virgil-sdk/examples")
    endif (INSTALL_EXAMPLES)
endforeach (SRC)

if (INSTALL_EXAMPLES)
    install (DIRECTORY "data/" DESTINATION "share/doc/virgil-sdk/examples")
endif (INSTALL_EXAMPLES)
