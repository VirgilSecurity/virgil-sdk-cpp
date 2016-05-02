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

#include <virgil/sdk/models/CardModel.h>

#include <virgil/sdk/models/IdentityModel.h>
#include <virgil/sdk/models/PublicKeyModel.h>

using virgil::sdk::models::CardModel;
using virgil::sdk::models::IdentityModel;
using virgil::sdk::models::PublicKeyModel;

CardModel::CardModel(const std::string& id, const std::string& createdAt, const std::string& hash,
                     const IdentityModel& cardIdentity, const std::map<std::string, std::string>& data,
                     const PublicKeyModel& publicKey, const bool confirmed)
        : id_(id),
          createdAt_(createdAt),
          hash_(hash),
          cardIdentity_(cardIdentity),
          data_(data),
          publicKey_(publicKey),
          confirmed_(confirmed) {
}

bool CardModel::authorizedBy() const {
    return confirmed_;
}

const std::string CardModel::getId() const {
    return id_;
}

const std::string CardModel::getCreatedAt() const {
    return createdAt_;
}

const std::string CardModel::getHash() const {
    return hash_;
}

const IdentityModel CardModel::getCardIdentity() const {
    return cardIdentity_;
}

const std::map<std::string, std::string> CardModel::getData() const {
    return data_;
}

const PublicKeyModel CardModel::getPublicKey() const {
    return publicKey_;
}
