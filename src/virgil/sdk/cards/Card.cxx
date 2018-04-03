/**
 * Copyright (C) 2018 Virgil Security Inc.
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

#include <virgil/sdk/cards/Card.h>

using virgil::sdk::cards::Card;
using virgil::sdk::crypto::keys::PublicKey;
using virgil::sdk::VirgilByteArray;
using virgil::sdk::cards::CardSignature;
using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::client::models::RawSignature;

Card::Card(const std::string &identifier, const std::string &identity,
           const virgil::sdk::crypto::keys::PublicKey &publicKey, const std::string &version,
           const std::time_t &createdAt, const virgil::sdk::VirgilByteArray &contentSnapshot, const bool &isOutdated,
           const std::vector<CardSignature> &signatures, const std::string &previousCardId,
           const std::shared_ptr<virgil::sdk::cards::Card> &previousCard)
: identifier_(identifier), identity_(identity), publicKey_(publicKey), version_(version),
  createdAt_(createdAt), contentSnapshot_(contentSnapshot), isOutdated_(isOutdated),
  signatures_(signatures), previousCardId_(previousCardId), previousCard_(previousCard) {}

const std::string& Card::identifier() const { return identifier_; }

const std::string& Card::identity() const { return identity_; }

const PublicKey& Card::publicKey() const { return publicKey_; }

const std::string& Card::version() const { return version_; }

const std::time_t& Card::createdAt() const { return createdAt_; }

const VirgilByteArray& Card::contentSnapshot() const { return contentSnapshot_; }

const bool& Card::isOutdated() const { return isOutdated_; }

const std::vector<CardSignature>& Card::signatures() const { return signatures_; }

const std::string& Card::previousCardId() const { return previousCardId_; }

const std::shared_ptr<Card>& Card::previousCard() const { return previousCard_; }

void Card::previousCard(const std::shared_ptr<virgil::sdk::cards::Card> &newPreviousCard) {
    previousCard_ = newPreviousCard;
}

void Card::isOutdated(const bool &newIsOutdated) {
    isOutdated_ = newIsOutdated;
}

void Card::previousCardId(const std::string &newPreviousCardId) {
    previousCardId_ = newPreviousCardId;
}

RawSignedModel Card::getRawCard() const {
    auto rawCard = RawSignedModel(contentSnapshot_);

    for (auto& cardSignature : signatures_) {
        auto signature = RawSignature(cardSignature.signer(),
                                      cardSignature.signature(),
                                      cardSignature.snapshot());
        rawCard.addSignature(signature);
    }

    return rawCard;
}