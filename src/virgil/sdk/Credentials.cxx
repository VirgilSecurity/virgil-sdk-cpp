/**
 * Copyright (C) 2015 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <virgil/crypto/VirgilByteArrayUtils.h>

#include <virgil/sdk/Credentials.h>

using virgil::sdk::Credentials;


Credentials::Credentials(const std::vector<unsigned char>& privateKey, const std::string& privateKeyPassword)
        : privateKey_(privateKey), privateKeyPassword_(privateKeyPassword) {

}

Credentials::~Credentials() noexcept {
    cleanup();
}

bool Credentials::isValid() const {
    return !privateKey_.empty();
}

void Credentials::cleanup() noexcept {
    if (!privateKey_.empty()) {
        virgil::crypto::bytes_zeroize(privateKey_);
    }

    if (!privateKeyPassword_.empty()) {
        virgil::crypto::string_zeroize(privateKeyPassword_);
    }
}

const std::vector<unsigned char>& Credentials::privateKey() const {
    return privateKey_;
}

const std::string& Credentials::privateKeyPassword() const {
    return privateKeyPassword_;
}
