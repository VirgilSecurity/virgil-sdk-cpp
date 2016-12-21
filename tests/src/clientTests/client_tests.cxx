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

#include <thread>
#include <memory>

#include <TestConst.h>
#include <TestUtils.h>

#include <virgil/sdk/client/Client.h>
#include <virgil/sdk/client/CardValidator.h>

using virgil::sdk::client::Client;
using virgil::sdk::client::ServiceConfig;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::SearchCardsCriteria;
using virgil::sdk::client::models::CardScope;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestUtils;
using virgil::sdk::client::CardValidator;
using virgil::crypto::foundation::VirgilBase64;
using virgil::sdk::client::interfaces::CardValidatorInterface;

TEST_CASE("test001_CreateCard", "[client]") {
    TestConst consts;
    TestUtils utils(consts);

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());
    auto validator = std::make_unique<CardValidator>(utils.crypto());
    validator->addVerifier(consts.applicationId(), VirgilBase64::decode(consts.applicationPublicKeyBase64()));
    serviceConfig.cardValidator(std::move(validator));

    Client client(std::move(serviceConfig));

    auto createCardRequest = utils.instantiateCreateCardRequest();

    auto future = client.createCard(createCardRequest);

    auto card = future.get();

    REQUIRE(utils.checkCardEquality(card, createCardRequest));
}

TEST_CASE("test002_CreateCardWithDataAndInfo", "[client]") {
    TestConst consts;
    TestUtils utils(consts);

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());
    auto validator = std::make_unique<CardValidator>(utils.crypto());
    validator->addVerifier(consts.applicationId(), VirgilBase64::decode(consts.applicationPublicKeyBase64()));
    serviceConfig.cardValidator(std::move(validator));

    Client client(std::move(serviceConfig));

    std::unordered_map<std::string, std::string> data;
    data["some_random_key1"] = "some_random_data1";
    data["some_random_key2"] = "some_random_data2";

    auto createCardRequest = utils.instantiateCreateCardRequest(data, "mac", "very_good_mac");

    auto future = client.createCard(createCardRequest);

    auto card = future.get();

    REQUIRE(utils.checkCardEquality(card, createCardRequest));
}

TEST_CASE("test003_SearchCards", "[client]") {
    TestConst consts;
    TestUtils utils(consts);

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());
    auto validator = std::make_unique<CardValidator>(utils.crypto());
    validator->addVerifier(consts.applicationId(), VirgilBase64::decode(consts.applicationPublicKeyBase64()));
    serviceConfig.cardValidator(std::move(validator));

    Client client(std::move(serviceConfig));

    auto createCardRequest = utils.instantiateCreateCardRequest();

    auto future = client.createCard(createCardRequest);

    auto card = future.get();

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    auto future2 = client.searchCards(
            SearchCardsCriteria::createCriteria(CardScope::application, card.identityType(), { card.identity() }));

    auto foundCards = future2.get();

    REQUIRE(foundCards.size() == 1);
    REQUIRE(utils.checkCardEquality(card, foundCards[0]));
}

TEST_CASE("test004_GetCard", "[client]") {
    TestConst consts;
    TestUtils utils(consts);

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());
    auto validator = std::make_unique<CardValidator>(utils.crypto());
    validator->addVerifier(consts.applicationId(), VirgilBase64::decode(consts.applicationPublicKeyBase64()));
    serviceConfig.cardValidator(std::move(validator));

    Client client(std::move(serviceConfig));

    auto createCardRequest = utils.instantiateCreateCardRequest();

    auto future = client.createCard(createCardRequest);

    auto card = future.get();

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    auto future2 = client.getCard(card.identifier());

    auto foundCard = future2.get();

    REQUIRE(utils.checkCardEquality(card, foundCard));
}

TEST_CASE("test005_RevokeCard", "[client]") {
    TestConst consts;
    TestUtils utils(consts);

    auto serviceConfig = ServiceConfig::createConfig(consts.applicationToken());
    auto validator = std::make_unique<CardValidator>(utils.crypto());
    validator->addVerifier(consts.applicationId(), VirgilBase64::decode(consts.applicationPublicKeyBase64()));
    serviceConfig.cardValidator(std::move(validator));

    Client client(std::move(serviceConfig));

    auto createCardRequest = utils.instantiateCreateCardRequest();

    auto future = client.createCard(createCardRequest);

    auto card = future.get();

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    auto revokeRequest = utils.instantiateRevokeCardRequest(card);

    auto future2 = client.revokeCard(revokeRequest);

    future2.get();

    auto future3 = client.getCard(card.identifier());

    bool errorWasThrown = false;
    try {
        future3.get();
    }
    catch (...) {
        errorWasThrown = true;
    }

    REQUIRE(errorWasThrown);
}