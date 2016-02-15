#!/bin/bash
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
# Performs code formatting by using .clang-format configuration file located in the project root folder
#

function abspath() {
  (
    if [ -d "$1" ]; then
        cd "$1" && pwd -P
    else
        echo "$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
    fi
  )
}

SCRIPT_DIR=$(dirname "$(abspath "${BASH_SOURCE[0]}")")

SDK_INC_FILES=$(find "$(abspath ${SCRIPT_DIR}/../include)" -name "*.h")
SDK_SRC_FILES=$(find "$(abspath ${SCRIPT_DIR}/../src)" -name "*.cxx")

TESTS_INC_FILES=$(find "$(abspath ${SCRIPT_DIR}/../tests)" -name "*.h")
TESTS_SRC_FILES=$(find "$(abspath ${SCRIPT_DIR}/../tests)" -name "*.cxx")

EXAMPLES_INC_FILES=$(find "$(abspath ${SCRIPT_DIR}/../examples)" -name "*.h")
EXAMPLES_SRC_FILES=$(find "$(abspath ${SCRIPT_DIR}/../examples)" -name "*.cxx")

for f in ${SDK_INC_FILES} ${SDK_SRC_FILES} \
         ${TESTS_INC_FILES} ${TESTS_SRC_FILES} \
        ${EXAMPLES_INC_FILES} ${EXAMPLES_SRC_FILES}
do
    clang-format "$f" > "$f.formatted" && mv "$f.formatted" "$f"
done
