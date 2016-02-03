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
using virgil::sdk::model::VirgilCardIdentity;
using virgil::sdk::model::Identity;
using virgil::sdk::util::JsonKey;
using virgil::sdk::io::Marshaller;

using PairStrStr = std::pair<std::string, std::string>;


TEST_CASE("JSON VirgilCard -> VirgilCard - FAILED", "class Marshaller") {
    json  jsonVirgilCard = virgil::test::getJsonVirgilCard();
    VirgilCard trueVirgilCard = virgil::test::getVirgilCard();
    // JSON VirgilCard -> VirgilCard
    VirgilCard testVirgilCard = Marshaller<VirgilCard>::fromJson(jsonVirgilCard.dump(4));

    REQUIRE( trueVirgilCard.getCreatedAt() == testVirgilCard.getCreatedAt() );
    REQUIRE( trueVirgilCard.getData() == testVirgilCard.getData() );
    REQUIRE( trueVirgilCard.getHash() == testVirgilCard.getHash() );
    REQUIRE( trueVirgilCard.getId() == testVirgilCard.getId() );

    VirgilCardIdentity trueVirgilCardIdentity = trueVirgilCard.getIdentity();
    VirgilCardIdentity testVirgilCardIdentity = testVirgilCard.getIdentity();

    REQUIRE( trueVirgilCardIdentity.getId() == testVirgilCardIdentity.getId() );
    REQUIRE( trueVirgilCardIdentity.getCreatedAt() == testVirgilCardIdentity.getCreatedAt() );

    Identity trueIdentity = trueVirgilCardIdentity. getIdentity();
    Identity testIdentity = testVirgilCardIdentity.getIdentity();

    REQUIRE( trueIdentity.getTypeAsString() == testIdentity.getTypeAsString() );
    REQUIRE( trueIdentity.getValue() == testIdentity.getValue() );

    PublicKey truePublicKey = trueVirgilCard.getPublicKey();
    PublicKey testPublicKey = testVirgilCard.getPublicKey();

    REQUIRE( truePublicKey.getId() == testPublicKey.getId() );
    REQUIRE( truePublicKey.getCreatedAt() == testPublicKey.getCreatedAt() );
    REQUIRE( truePublicKey.getKey() == testPublicKey.getKey() );
}

TEST_CASE("VirgilCard -> JSON VirgilCard - FAILED", "class Marshaller") {
    VirgilCard virgilCard = virgil::test::getVirgilCard();
    // VirgilCard -> JSON VirgilCard
    std::string testJsonVirgilCard = Marshaller<VirgilCard>::toJson(virgilCard);
    std::string trueJsonVirgilCard = virgil::test::getJsonVirgilCard().dump();
    REQUIRE( trueJsonVirgilCard == testJsonVirgilCard );
}

TEST_CASE("JSON VirgilCards -> std::vector<VirgilCard> - FAILED", "class Marshaller") {
    json jsonVirgilCards = virgil::test::getJsonVirgilCards();
    std::vector<VirgilCard> trueVirgilCard = virgil::test::getVirgilCards();
    std::vector<VirgilCard> testVirgilCards =  virgil::sdk::io::fromJsonVirgilCards( jsonVirgilCards.dump(4) );

    REQUIRE( trueVirgilCard.size() == testVirgilCards.size() );
    for(const auto& i: trueVirgilCard) {
        for(const auto& j: testVirgilCards) {
            REQUIRE( i.getCreatedAt() == j.getCreatedAt() );
            REQUIRE( i.getData() == j.getData() );
            REQUIRE( i.getHash() == j.getHash() );
            REQUIRE( i.getId() == j.getId() );

            VirgilCardIdentity trueVirgilCardIdentity = i.getIdentity();
            VirgilCardIdentity testVirgilCardIdentity = j.getIdentity();

            REQUIRE( trueVirgilCardIdentity.getId() == testVirgilCardIdentity.getId() );
            REQUIRE( trueVirgilCardIdentity.getCreatedAt() == testVirgilCardIdentity.getCreatedAt() );

            Identity trueIdentity = trueVirgilCardIdentity. getIdentity();
            Identity testIdentity = testVirgilCardIdentity.getIdentity();

            REQUIRE( trueIdentity.getTypeAsString() == testIdentity.getTypeAsString() );
            REQUIRE( trueIdentity.getValue() == testIdentity.getValue() );

            PublicKey truePublicKey = i.getPublicKey();
            PublicKey testPublicKey = j.getPublicKey();

            REQUIRE( truePublicKey.getId() == testPublicKey.getId() );
            REQUIRE( truePublicKey.getCreatedAt() == testPublicKey.getCreatedAt() );
            REQUIRE( truePublicKey.getKey() == testPublicKey.getKey() );
        }
    }
}

TEST_CASE("std::vector<VirgilCard> -> JSON Virgil Cards - FAILED", "class Marshaller") {
    std::vector<VirgilCard> virgilCards = virgil::test::getVirgilCards();

    std::string jsonStrVirgilCards = virgil::sdk::io::toJsonVirgilCards(virgilCards, 4);

    //std::cout << jsonStrVirgilCards << std::endl;


}
