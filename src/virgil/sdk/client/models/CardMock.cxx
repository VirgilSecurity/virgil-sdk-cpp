/**
 * Copyright (C) 2016 Virgil Security Inc.
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

#include <virgil/sdk/client/models/CardMock.h>
#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/models/serialization/JsonSerializer.h>
#include <virgil/sdk/client/models/serialization/JsonDeserializer.h>

static_assert(!std::is_abstract<virgil::sdk::client::models::CardMock>(), "Card must not be abstract.");

using virgil::sdk::client::models::CardMock;
using virgil::sdk::client::models::CardScope;
using virgil::sdk::client::models::responses::CardResponse;
using virgil::sdk::client::models::serialization::JsonDeserializer;
using virgil::sdk::client::models::serialization::JsonSerializer;
using virgil::sdk::VirgilByteArrayUtils;

CardMock CardMock::buildCard(const responses::CardResponse &cardResponse) {
    return CardMock(cardResponse, cardResponse.identifier(), cardResponse.model().identity(),
                cardResponse.model().identityType(), cardResponse.model().publicKeyData(), cardResponse.model().data(),
                cardResponse.model().scope(), cardResponse.model().info(), cardResponse.createdAt(),
                cardResponse.cardVersion());
}

CardMock::CardMock(CardResponse cardResponse, std::string identifier, std::string identity, std::string identityType,
           VirgilByteArray publicKeyData, std::unordered_map<std::string, std::string> data, CardScope scope,
           std::unordered_map<std::string, std::string> info, std::string createdAt, std::string cardVersion)
        : cardResponse_(std::move(cardResponse)), identifier_(std::move(identifier)), identity_(std::move(identity)),
          identityType_(std::move(identityType)), publicKeyData_(std::move(publicKeyData)), data_(std::move(data)),
          scope_(scope), info_(std::move(info)), createdAt_(std::move(createdAt)),
          cardVersion_(std::move(cardVersion)) {
}

std::string CardMock::exportAsString() const {
    auto json = JsonSerializer<CardResponse>::toJson(cardResponse_);
    return VirgilBase64::encode(VirgilByteArrayUtils::stringToBytes(json));
}

CardMock CardMock::importFromString(const std::string &data) {
    auto jsonStr = VirgilByteArrayUtils::bytesToString(VirgilBase64::decode(data));
    auto cardResponse = JsonDeserializer<CardResponse>::fromJsonString(jsonStr);

    return CardMock::buildCard(cardResponse);
}