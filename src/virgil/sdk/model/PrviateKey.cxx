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

#include <virgil/sdk/model/PrivateKey.h>

using virgil::sdk::model::PrivateKey;

using virgil::crypto::VirgilByteArray;


PrivateKey::PrivateKey(const std::string& virgilCardId, const std::string& key)
     : virgilCardId_(virgilCardId), key_( virgil::crypto::str2bytes(key) ) {

}

PrivateKey::PrivateKey(const std::string& virgilCardId, const VirgilByteArray& key)
     : virgilCardId_(virgilCardId), key_(key) {

}

PrivateKey::~PrivateKey() noexcept {
    cleanup();
}

std::string PrivateKey::getVirgilCardId() const {
    return virgilCardId_;
}

std::string PrivateKey::getKeyStr() const {
    return virgil::crypto::bytes2str(key_);
}

VirgilByteArray PrivateKey::getKeyByteArray() const {
    return key_;
}

void PrivateKey::setVirgilCardId(const std::string& virgilCardId) {
    virgilCardId_ = virgilCardId;
}

void PrivateKey::setKeyStr(const std::string& key) {
    key_ = virgil::crypto::str2bytes(key);
}

void PrivateKey::setKeyByteArray(const VirgilByteArray& key) {
    key_ = key;
}

void PrivateKey::cleanup() noexcept {
    if (!key_.empty()) {
        virgil::crypto::bytes_zeroize(key_);
    }
}
