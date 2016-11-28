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

#include <catch.hpp>

#include <chrono>
#include <thread>

#include <TestConst.h>
#include <TestUtils.h>

#include <virgil/sdk/client/models/requests/CreateCardRequest.h>
#include <virgil/sdk/client/Client.h>

using virgil::sdk::client::Client;
using virgil::sdk::client::ClientInterface;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestUtils;

TEST_CASE("test001_CreateCard", "[client]") {
    TestConst consts;

    auto client = Client(consts.applicationToken(),
                         "https://cards.virgilsecurity.com/");
    Crypto crypto;

    TestUtils utils(crypto, consts);

    auto createCardRequest = utils.instantiateCreateCardRequest();

    auto future = client.createCard(createCardRequest);

    auto card = future.get();

    REQUIRE(utils.checkCardEquality(card, createCardRequest));
}

TEST_CASE("test002_CreateCardWithDataAndInfo", "[client]") {
    TestConst consts;

    auto client = Client(consts.applicationToken(),
                         "https://cards.virgilsecurity.com/");
    Crypto crypto;

    TestUtils utils(crypto, consts);

    std::unordered_map<std::string, std::string> data;
    data["some_random_key1"] = "some_random_data1";
    data["some_random_key2"] = "some_random_data2";

    auto createCardRequest = utils.instantiateCreateCardRequest(data, "mac", "very_good_mac");

    auto future = client.createCard(createCardRequest);

    auto card = future.get();

    REQUIRE(utils.checkCardEquality(card, createCardRequest));
}

TEST_CASE("test004_GetCard", "[client]") {
    TestConst consts;

    auto client = Client(consts.applicationToken(),
                         "https://cards.virgilsecurity.com/");

    Crypto crypto;

    TestUtils utils(crypto, consts);

    auto createCardRequest = utils.instantiateCreateCardRequest();

    auto future = client.createCard(createCardRequest);

    auto card = future.get();

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    auto future2 = client.getCard(card.identifier());

    auto foundCard = future2.get();

    REQUIRE(utils.checkCardEquality(card, foundCard));
}
