/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#include <catch.hpp>

#include <thread>
#include <memory>

#include <TestConst.h>
#include <TestUtils.h>

#include <virgil/sdk/client/CardClient.h>

#include <virgil/sdk/client/models/RawCardContent.h>
#include <virgil/sdk/cards/ModelSigner.h>
#include <virgil/sdk/cards/CardManager.h>
#include <virgil/sdk/cards/verification/VirgilCardVerifier.h>
#include <virgil/sdk/VirgilSdkError.h>

using virgil::sdk::client::CardClient;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestUtils;
using virgil::sdk::client::models::RawCardContent;
using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::cards::ModelSigner;
using virgil::sdk::VirgilBase64;
using virgil::sdk::cards::CardManager;
using virgil::sdk::cards::verification::VirgilCardVerifier;
using virgil::sdk::cards::Card;
using virgil::sdk::client::networking::errors::Error;

TEST_CASE("test001_CreateCard", "[client]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto token = utils.getToken("identity");

    CardClient cardClient(consts.ServiceURL());
    ModelSigner modelSigner(crypto);

    auto keyPair = crypto->generateKeyPair();
    auto publicKeyData = crypto->exportPublicKey(keyPair.publicKey());

    RawCardContent content("identity", publicKeyData, std::time(0));
    auto snapshot = content.snapshot();

    RawSignedModel rawCard(snapshot);

    modelSigner.selfSign(rawCard, keyPair.privateKey());
    REQUIRE(rawCard.signatures().size() == 1);

    auto card = CardManager::parseCard(rawCard, crypto);

    auto future = cardClient.publishCard(rawCard, token.stringRepresentation());

    auto responseRawCard = future.get();
    auto publishedCard = CardManager::parseCard(responseRawCard, crypto);

    REQUIRE(utils.isCardsEqual(card, publishedCard));

    auto verifier = VirgilCardVerifier(crypto);
    REQUIRE(verifier.verifyCard(publishedCard));
}

TEST_CASE("test002_GetCard", "[client]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto token = utils.getToken("identity");

    CardClient cardClient(consts.ServiceURL());
    ModelSigner modelSigner(crypto);

    auto keyPair = crypto->generateKeyPair();
    auto publicKeyData = crypto->exportPublicKey(keyPair.publicKey());

    RawCardContent content("identity", publicKeyData, std::time(0));
    auto snapshot = content.snapshot();

    RawSignedModel rawCard(snapshot);

    modelSigner.selfSign(rawCard, keyPair.privateKey());
    REQUIRE(rawCard.signatures().size() == 1);

    auto card = CardManager::parseCard(rawCard, crypto);

    auto future = cardClient.publishCard(rawCard, token.stringRepresentation());
    auto publishedRawCard = future.get();
    auto publishedCard = CardManager::parseCard(publishedRawCard, crypto);

    auto getFuture = cardClient.getCard(publishedCard.identifier(), token.stringRepresentation());
    auto getCardResponse = getFuture.get();
    auto gotCard = CardManager::parseCard(getCardResponse.rawCard(), crypto);

    REQUIRE(utils.isCardsEqual(gotCard, publishedCard));

    auto verifier = VirgilCardVerifier(crypto);
    REQUIRE(verifier.verifyCard(gotCard));
}

TEST_CASE("test003_SearchCards", "[client]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto identity = utils.getRandomString();
    auto token = utils.getToken(identity);

    CardClient cardClient(consts.ServiceURL());
    ModelSigner modelSigner(crypto);

    auto keyPair = crypto->generateKeyPair();
    auto publicKeyData = crypto->exportPublicKey(keyPair.publicKey());

    RawCardContent content(identity, publicKeyData, std::time(0));
    auto snapshot = content.snapshot();

    RawSignedModel rawCard(snapshot);

    modelSigner.selfSign(rawCard, keyPair.privateKey());
    REQUIRE(rawCard.signatures().size() == 1);

    auto card = CardManager::parseCard(rawCard, crypto);

    auto future = cardClient.publishCard(rawCard, token.stringRepresentation());
    auto publishedRawCard = future.get();
    auto publishedCard = CardManager::parseCard(publishedRawCard, crypto);

    auto searchFuture = cardClient.searchCards(publishedCard.identity(), token.stringRepresentation());
    auto rawCards = searchFuture.get();
    REQUIRE(!rawCards.empty());

    bool found = false;
    for (auto& element : rawCards) {
        auto foundCard = CardManager::parseCard(element, crypto);
        if (utils.isCardsEqual(foundCard, publishedCard)) {
            found = true;
            auto verifier = VirgilCardVerifier(crypto);
            REQUIRE(verifier.verifyCard(foundCard));

            break;
        }
    }
    REQUIRE(found);
}

TEST_CASE("test004_STC25", "[client]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto token = utils.getTokenWithWrongPrivateKey("identity");

    CardClient cardClient(consts.ServiceURL());
    ModelSigner modelSigner(crypto);

    auto keyPair = crypto->generateKeyPair();
    auto publicKeyData = crypto->exportPublicKey(keyPair.publicKey());

    RawCardContent content("identity", publicKeyData, std::time(0));
    auto snapshot = content.snapshot();

    RawSignedModel rawCard(snapshot);

    modelSigner.selfSign(rawCard, keyPair.privateKey());
    REQUIRE(rawCard.signatures().size() == 1);

    auto card = CardManager::parseCard(rawCard, crypto);

    bool errorWasThrown = false;
    try {
        auto future = cardClient.publishCard(rawCard, token.stringRepresentation());
        auto publishedRawCard = future.get();
    } catch (Error& error) {
        REQUIRE(error.httpErrorCode() == 401);
        errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);

    errorWasThrown = false;
    try {
        auto searchFuture = cardClient.searchCards("identity", token.stringRepresentation());
        auto rawCards = searchFuture.get();
    } catch (Error& error) {
        REQUIRE(error.httpErrorCode() == 401);
        errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);

    errorWasThrown = false;
    try {
        auto getFuture = cardClient.getCard(card.identifier(), token.stringRepresentation());
        auto gotRawCard = getFuture.get();
    } catch (Error& error) {
        REQUIRE(error.httpErrorCode() == 401);
        errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);
}

TEST_CASE("test005_STC27", "[client]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto token = utils.getToken("identity");

    CardClient cardClient(consts.ServiceURL());
    ModelSigner modelSigner(crypto);

    auto keyPair = crypto->generateKeyPair();
    auto publicKeyData = crypto->exportPublicKey(keyPair.publicKey());

    RawCardContent content("another_identity", publicKeyData, std::time(0));
    auto snapshot = content.snapshot();

    RawSignedModel rawCard(snapshot);

    modelSigner.selfSign(rawCard, keyPair.privateKey());
    REQUIRE(rawCard.signatures().size() == 1);

    bool errorWasThrown = false;
    try {
        auto future = cardClient.publishCard(rawCard, token.stringRepresentation());
        auto responseRawCard = future.get();
    } catch (...) {
        errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);
}