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

/**
 * @file test_virgil_card_marshaller.cxx
 * @brief Convert json -> CardModels.
 */

#include <string>

#include <catch.hpp>

#include <helpers.h>

#include <virgil/sdk/io/Marshaller.h>

using json = nlohmann::json;

using virgil::sdk::models::CardModel;
using virgil::sdk::models::PublicKeyModel;
using virgil::sdk::models::IdentityModel;
using virgil::sdk::dto::Identity;
using virgil::sdk::util::JsonKey;
using virgil::sdk::io::Marshaller;

TEST_CASE("JSON CardModel -> CardModel - FAILED", "class Marshaller") {
    json jsonCard = virgil::test::getJsonCard();
    CardModel testCard = Marshaller<CardModel>::fromJson(jsonCard.dump(4));
    CardModel trueCard = virgil::test::getCard();
    REQUIRE(virgil::test::getCard() == testCard);
}

TEST_CASE("Card -> JSON CardModel - FAILED", "class Marshaller") {
    CardModel card = virgil::test::getCard();
    std::string testJsonCard = Marshaller<CardModel>::toJson<4>(card);
    REQUIRE(virgil::test::getJsonCard().dump(4) == testJsonCard);
}

// Json Response = Json Public Key + Json Cards
TEST_CASE("Json Response -> std::vector<CardModel> - FAILED", "class Marshaller") {
    json jsonResponse = virgil::test::getJsonResponseCards();
    std::vector<CardModel> testCards = virgil::sdk::io::cardsFromJson(jsonResponse.dump());
    std::vector<CardModel> trueCards = virgil::test::getCards();
    REQUIRE(trueCards == testCards);
}

TEST_CASE("Json Cards -> std::vector<CardModel> - FAILED", "class Marshaller") {
    json jsonCards = virgil::test::getJsonCards();
    std::vector<CardModel> testCards = virgil::sdk::io::cardsFromJson(jsonCards.dump());
    std::vector<CardModel> trueCards = virgil::test::getCards();
    REQUIRE(trueCards == testCards);
}

TEST_CASE("std::vector<CardModel> -> JSON Virgil Cards - FAILED", "class Marshaller") {
    std::vector<CardModel> cards = virgil::test::getCards();
    std::string testJsonCards = virgil::sdk::io::cardsToJson(cards, 4);
    REQUIRE(virgil::test::getJsonCards().dump(4) == testJsonCards);
}
