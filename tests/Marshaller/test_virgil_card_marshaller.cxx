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
 * @brief Convert json -> Cards.
 */

#include <string>
#include <iostream>

#include "../catch.hpp"

#include "../helpers.h"

#include <virgil/sdk/io/Marshaller.h>

using json = nlohmann::json;

using virgil::sdk::model::Card;
using virgil::sdk::model::PublicKey;
using virgil::sdk::model::CardIdentity;
using virgil::sdk::model::Identity;
using virgil::sdk::util::JsonKey;
using virgil::sdk::io::Marshaller;

TEST_CASE("JSON Card -> Card - FAILED", "class Marshaller") {
    json jsonCard = virgil::test::getJsonCard();
    // JSON Card -> Card
    Card testCard = Marshaller<Card>::fromJson(jsonCard.dump(4));
    Card trueCard = virgil::test::getCard();
    REQUIRE(virgil::test::getCard() == testCard);
}

TEST_CASE("Card -> JSON Card - FAILED", "class Marshaller") {
    Card card = virgil::test::getCard();
    // Card -> JSON Card
    std::string testJsonCard = Marshaller<Card>::toJson<4>(card);
    REQUIRE(virgil::test::getJsonCard().dump(4) == testJsonCard);
}

// Json Response = Json Public Key + Json Cards
TEST_CASE("Json Response -> std::vector<Card> - FAILED", "class Marshaller") {
    json jsonResponse = virgil::test::getJsonResponseCards();
    std::vector<Card> testCards = virgil::sdk::io::cardsFromJson(jsonResponse.dump());
    std::vector<Card> trueCards = virgil::test::getCards();
    REQUIRE(trueCards == testCards);
}

TEST_CASE("Json Cards -> std::vector<Card> - FAILED", "class Marshaller") {
    json jsonCards = virgil::test::getJsonCards();
    std::vector<Card> testCards = virgil::sdk::io::cardsFromJson(jsonCards.dump());
    std::vector<Card> trueCards = virgil::test::getCards();
    REQUIRE(trueCards == testCards);
}

TEST_CASE("std::vector<Card> -> JSON Virgil Cards - FAILED", "class Marshaller") {
    std::vector<Card> cards = virgil::test::getCards();
    std::string testJsonCards = virgil::sdk::io::cardsToJson(cards, 4);
    REQUIRE(virgil::test::getJsonCards().dump(4) == testJsonCards);
}
