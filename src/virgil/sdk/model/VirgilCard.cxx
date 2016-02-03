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

#include <virgil/sdk/model/PublicKey.h>
#include <virgil/sdk/model/VirgilCard.h>

using virgil::sdk::model::PublicKey;
using virgil::sdk::model::VirgilCard;
using virgil::sdk::model::VirgilCardIdentity;


VirgilCard::VirgilCard(const bool confirme, const std::string& id, const std::string& createdAt,
        const std::string& hash, const VirgilCardIdentity& identity, const std::vector<PairStrStr>& data,
        const PublicKey& publicKey)
        : confirme_(confirme), 
        id_(id), 
        createdAt_(createdAt), 
        hash_(hash), 
        identity_(identity),
        data_(data),
        publicKey_(publicKey){

}

bool VirgilCard::isConfirmed() const {
    return confirme_;
}

std::string VirgilCard::getId() const {
    return id_;
}

std::string VirgilCard::getCreatedAt() const {
    return createdAt_;
}

std::string VirgilCard::getHash() const {
    return hash_;
}

VirgilCardIdentity VirgilCard::getIdentity() const {
    return identity_;
}

std::vector<PairStrStr> VirgilCard::getData() const {
    return data_;
}

PublicKey VirgilCard::getPublicKey() const {
    return publicKey_;
}

void VirgilCard::setConfirme(const bool confirme) {
    confirme_ = confirme;
}

void VirgilCard::setId(const std::string& id) {
    id_ = id;
}

void VirgilCard::setCreatedAt(const std::string& createdAt) {
    createdAt_ = createdAt;
}

void VirgilCard::setHash(const std::string& hash) {
    hash_ = hash;
}

void VirgilCard::setIdentity(const VirgilCardIdentity& identity) {
    identity_ = identity;
}

void VirgilCard::setData(const std::vector<PairStrStr>& data) {
    data_ = data;
}

void VirgilCard::setPublicKey(const PublicKey& publicKey) {
    publicKey_ = publicKey;
}
