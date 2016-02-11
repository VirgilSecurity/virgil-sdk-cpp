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
 * @brief Convert json -> VirgilCards.
 */

#include <string>
#include <iostream>

#include "../catch.hpp"

#include "../helpers.h"

#include <virgil/sdk/io/Marshaller.h>

using json = nlohmann::json;

using virgil::sdk::model::VirgilCard;
using virgil::sdk::model::PublicKey;
using virgil::sdk::model::IdentityExtended;
using virgil::sdk::model::Identity;
using virgil::sdk::util::JsonKey;
using virgil::sdk::io::Marshaller;


TEST_CASE("JSON VirgilCard -> VirgilCard - FAILED", "class Marshaller") {
    json  jsonVirgilCard = virgil::test::getJsonVirgilCard();
    // JSON VirgilCard -> VirgilCard
    VirgilCard testVirgilCard = Marshaller<VirgilCard>::fromJson(jsonVirgilCard.dump(4));
    VirgilCard trueVirgilCard = virgil::test::getVirgilCard();
    REQUIRE( virgil::test::getVirgilCard() == testVirgilCard );
}

TEST_CASE("VirgilCard -> JSON VirgilCard - FAILED", "class Marshaller") {
    VirgilCard virgilCard = virgil::test::getVirgilCard();
    // VirgilCard -> JSON VirgilCard
    std::string testJsonVirgilCard = Marshaller<VirgilCard>::toJson<4>(virgilCard);
    REQUIRE( virgil::test::getJsonVirgilCard().dump(4) == testJsonVirgilCard );
}

// Json Response = Json Public Key + Json VirgilCards
TEST_CASE("Json Response -> std::vector<VirgilCard> - FAILED", "class Marshaller") {
    json jsonResponse = virgil::test::getJsonResponseVirgilCards();
    std::vector<VirgilCard> testVirgilCards = virgil::sdk::io::fromJsonVirgilCards(jsonResponse.dump());
    std::vector<VirgilCard> trueVirgilCards = virgil::test::getVirgilCards();
    REQUIRE( trueVirgilCards == testVirgilCards );
}

TEST_CASE("Json VirgilCards -> std::vector<VirgilCard> - FAILED", "class Marshaller") {
    json jsonVirgilCards = virgil::test::getJsonVirgilCards();
    std::vector<VirgilCard> testVirgilCards = virgil::sdk::io::fromJsonVirgilCards(jsonVirgilCards.dump());
    std::vector<VirgilCard> trueVirgilCards = virgil::test::getVirgilCards();
    REQUIRE( trueVirgilCards == testVirgilCards );
}

TEST_CASE("std::vector<VirgilCard> -> JSON Virgil Cards - FAILED", "class Marshaller") {
    std::vector<VirgilCard> virgilCards = virgil::test::getVirgilCards();
    std::string testJsonVirgilCards = virgil::sdk::io::toJsonVirgilCards(virgilCards, 4);
    REQUIRE( virgil::test::getJsonVirgilCards().dump(4) == testJsonVirgilCards );
}
