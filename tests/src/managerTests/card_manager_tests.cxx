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
#include <TestData.h>

#include <virgil/sdk/cards/CardManager.h>
#include <virgil/sdk/cards/verification/VirgilCardVerifier.h>
#include <virgil/sdk/jwt/providers/GeneratorJwtProvider.h>
#include <virgil/sdk/VirgilSdkException.h>
#include <virgil/sdk/VirgilSdkError.h>
#include <stubs/VerifierTrueStub.h>
#include <stubs/CardClientStub_STC34.h>
#include <stubs/AccessTokenProviderStub_STC26.h>

using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestUtils;
using virgil::sdk::VirgilBase64;
using virgil::sdk::cards::CardManager;
using virgil::sdk::cards::verification::VirgilCardVerifier;
using virgil::sdk::cards::ModelSigner;
using virgil::sdk::cards::verification::VerifierCredentials;
using virgil::sdk::cards::verification::Whitelist;
using virgil::sdk::jwt::providers::GeneratorJwtProvider;
using virgil::sdk::jwt::JwtGenerator;
using virgil::sdk::cards::Card;
using virgil::sdk::VirgilSdkException;
using virgil::sdk::VirgilSdkError;
using virgil::sdk::test::stubs::VerifierStubFalse;
using virgil::sdk::test::stubs::CardClientStub_STC34;
using virgil::sdk::test::stubs::AccessTokenProviderStub_STC26;
using virgil::sdk::client::CardClientInterface;
using virgil::sdk::client::models::RawCardContent;

const auto testData = virgil::sdk::test::TestData();

TEST_CASE("test001_STC_13", "[card_manager]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto privateKeyStr = consts.ApiPrivateKey();
    auto privateKeyData = VirgilBase64::decode(privateKeyStr);
    auto privateKey = crypto->importPrivateKey(privateKeyData);

    auto identity = "identity";
    auto generator = JwtGenerator(privateKey, consts.ApiPublicKeyId(), crypto, consts.AppId(), 1000);
    auto provider = std::make_shared<GeneratorJwtProvider>(generator, identity);
    auto verifier = std::make_shared<VerifierStubFalse>();

    auto cardManager = CardManager(crypto, provider, verifier);

    auto rawCardStr = testData.dict()["STC-3.as_string"];
    bool errorWasThrown = false;
    try {
        cardManager.importCardFromBase64(rawCardStr);
    } catch (...) {
        errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);

    auto rawCardJson = testData.dict()["STC-3.as_json"];
    errorWasThrown = false;
    try {
        cardManager.importCardFromJson(rawCardJson);
    } catch (...) {
        errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);

    auto keyPair1 = crypto->generateKeyPair();
    errorWasThrown = false;
    try {
        auto publishFuture = cardManager.publishCard(keyPair1.privateKey(), keyPair1.publicKey());
        auto publishedCard = publishFuture.get();
    } catch (VirgilSdkException& e) {
        //FIXME make error handling easier?
        //if (e.condition().value() == static_cast<int>(VirgilSdkError::CardVerificationFailed))
            errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);

    auto rawCard = cardManager.generateRawCard(keyPair1.privateKey(), keyPair1.publicKey(), identity);
    errorWasThrown = false;
    try {
        auto publishFuture = cardManager.publishCard(rawCard);
        auto publishedCard = publishFuture.get();
    } catch (VirgilSdkException& e) {
            errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);

    auto existentIdentity = utils.getRandomString();
    auto verifier1 = std::make_shared<VirgilCardVerifier>(crypto);
    auto cardManager1 = CardManager(crypto, provider, verifier1);
    auto existentRawCard = cardManager1.generateRawCard(keyPair1.privateKey(), keyPair1.publicKey(), existentIdentity);
    auto future = cardManager1.publishCard(existentRawCard);
    auto existentCard = future.get();

    errorWasThrown = false;
    try {
        auto publishFuture = cardManager.getCard(existentCard.identifier());
        auto publishedCard = publishFuture.get();
    } catch (VirgilSdkException& e) {
            errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);

    errorWasThrown = false;
    try {
        auto publishFuture = cardManager.searchCards(existentIdentity);
        auto publishedCard = publishFuture.get();
    } catch (VirgilSdkException& e) {
            errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);
}

TEST_CASE("test002_STC_17", "[card_manager]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto privateKeyStr = consts.ApiPrivateKey();
    auto privateKeyData = VirgilBase64::decode(privateKeyStr);
    auto privateKey = crypto->importPrivateKey(privateKeyData);

    auto generator = JwtGenerator(privateKey, consts.ApiPublicKeyId(), crypto, consts.AppId(), 1000);
    auto provider = std::make_shared<GeneratorJwtProvider>(generator, "identity");
    auto verifier = std::make_shared<VirgilCardVerifier>(crypto);

    auto cardManager = CardManager(crypto, provider, verifier);
    auto keyPair = crypto->generateKeyPair();

    auto publishFuture = cardManager.publishCard(keyPair.privateKey(), keyPair.publicKey());
    auto publishedCard = publishFuture.get();
    REQUIRE(!publishedCard.isOutdated());

    auto getFuture = cardManager.getCard(publishedCard.identifier());
    auto gotCard = getFuture.get();

    REQUIRE(!gotCard.isOutdated());
    REQUIRE(utils.isCardsEqual(publishedCard, gotCard));
    REQUIRE(utils.isCardSignaturesEqual(publishedCard.signatures(), gotCard.signatures()));
}

TEST_CASE("test003_STC_18", "[card_manager]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto privateKeyStr = consts.ApiPrivateKey();
    auto privateKeyData = VirgilBase64::decode(privateKeyStr);
    auto privateKey = crypto->importPrivateKey(privateKeyData);

    auto generator = JwtGenerator(privateKey, consts.ApiPublicKeyId(), crypto, consts.AppId(), 1000);
    auto provider = std::make_shared<GeneratorJwtProvider>(generator, "identity");
    auto verifier = std::make_shared<VirgilCardVerifier>(crypto);

    auto cardManager = CardManager(crypto, provider, verifier);
    auto keyPair = crypto->generateKeyPair();

    std::unordered_map<std::string, std::string> dic = {
            {"key1", "data1"},
            {"key2", "data2"},
    };

    auto publishFuture = cardManager.publishCard(keyPair.privateKey(), keyPair.publicKey(),
                                                 "identity", std::string(), dic);
    auto publishedCard = publishFuture.get();
    REQUIRE(!publishedCard.isOutdated());

    auto getFuture = cardManager.getCard(publishedCard.identifier());
    auto gotCard = getFuture.get();

    REQUIRE(!gotCard.isOutdated());
    REQUIRE(utils.isCardsEqual(publishedCard, gotCard));
    REQUIRE(utils.isCardSignaturesEqual(publishedCard.signatures(), gotCard.signatures()));
}

TEST_CASE("test004_STC_19", "[card_manager]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto privateKeyStr = consts.ApiPrivateKey();
    auto privateKeyData = VirgilBase64::decode(privateKeyStr);
    auto privateKey = crypto->importPrivateKey(privateKeyData);

    auto generator = JwtGenerator(privateKey, consts.ApiPublicKeyId(), crypto, consts.AppId(), 1000);
    auto provider = std::make_shared<GeneratorJwtProvider>(generator, "identity");
    auto verifier = std::make_shared<VirgilCardVerifier>(crypto);

    auto cardManager = CardManager(crypto, provider, verifier);
    auto keyPair1 = crypto->generateKeyPair();

    std::unordered_map<std::string, std::string> dic = {
            {"key1", "data1"},
            {"key2", "data2"},
    };
    auto publishFuture1 = cardManager.publishCard(keyPair1.privateKey(), keyPair1.publicKey(),
                                                 "identity", std::string(), dic);
    auto publishedCard1 = publishFuture1.get();
    REQUIRE(!publishedCard1.isOutdated());

    auto keyPair2 = crypto->generateKeyPair();

    auto publishFuture2 = cardManager.publishCard(keyPair2.privateKey(), keyPair2.publicKey(),
                                                  "identity", publishedCard1.identifier());
    auto publishedCard2 = publishFuture2.get();
    REQUIRE(!publishedCard2.isOutdated());

    auto getFuture1 = cardManager.getCard(publishedCard1.identifier());
    auto gotCard1 = getFuture1.get();

    REQUIRE(gotCard1.isOutdated());

    auto getFuture2 = cardManager.getCard(publishedCard2.identifier());
    auto gotCard2 = getFuture2.get();

    REQUIRE(!gotCard2.isOutdated());
    REQUIRE(gotCard2.previousCardId() == publishedCard1.identifier());
    REQUIRE(utils.isCardsEqual(publishedCard2, gotCard2));
    REQUIRE(utils.isCardSignaturesEqual(publishedCard2.signatures(), gotCard2.signatures()));
}


TEST_CASE("test005_STC_20", "[card_manager]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto privateKeyStr = consts.ApiPrivateKey();
    auto privateKeyData = VirgilBase64::decode(privateKeyStr);
    auto privateKey = crypto->importPrivateKey(privateKeyData);

    auto identity = utils.getRandomString();
    auto generator = JwtGenerator(privateKey, consts.ApiPublicKeyId(), crypto, consts.AppId(), 1000);
    auto provider = std::make_shared<GeneratorJwtProvider>(generator, identity);
    auto verifier = std::make_shared<VirgilCardVerifier>(crypto);

    auto cardManager = CardManager(crypto, provider, verifier);
    auto keyPair1 = crypto->generateKeyPair();

    std::unordered_map<std::string, std::string> dic = {
            {"key1", "data1"},
            {"key2", "data2"},
    };
    auto publishFuture1 = cardManager.publishCard(keyPair1.privateKey(), keyPair1.publicKey(),
                                                  identity, std::string(), dic);
    auto publishedCard1 = publishFuture1.get();
    REQUIRE(!publishedCard1.isOutdated());

    auto keyPair2 = crypto->generateKeyPair();

    auto publishFuture2 = cardManager.publishCard(keyPair2.privateKey(), keyPair2.publicKey(),
                                                  identity, publishedCard1.identifier());
    auto publishedCard2 = publishFuture2.get();
    REQUIRE(!publishedCard2.isOutdated());

    auto keyPair3 = crypto->generateKeyPair();

    auto publishFuture3 = cardManager.publishCard(keyPair3.privateKey(), keyPair3.publicKey(), identity);
    auto publishedCard3 = publishFuture3.get();
    REQUIRE(!publishedCard3.isOutdated());

    auto searchFuture = cardManager.searchCards(identity);
    auto cards = searchFuture.get();

    publishedCard1.isOutdated(true);
    publishedCard2.previousCard(std::make_shared<Card>(publishedCard1));
    REQUIRE(cards.size() == 2);
    for (auto& card : cards) {
        if (card.identifier() == publishedCard2.identifier()) {
            REQUIRE(utils.isCardsEqual(card, publishedCard2));
            REQUIRE(utils.isCardSignaturesEqual(card.signatures(), publishedCard2.signatures()));
            REQUIRE(utils.isCardsEqual(*card.previousCard(), publishedCard1));
            REQUIRE(card.previousCardId() == publishedCard1.identifier());
        }
        else if (card.identifier() == publishedCard3.identifier()) {
            REQUIRE(utils.isCardsEqual(card, publishedCard3));
        } else {
            FAIL();
        }
    }
}

TEST_CASE("test006_STC_21", "[card_manager]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto privateKeyStr = consts.ApiPrivateKey();
    auto privateKeyData = VirgilBase64::decode(privateKeyStr);
    auto privateKey = crypto->importPrivateKey(privateKeyData);

    auto identity = "identity";
    auto generator = JwtGenerator(privateKey, consts.ApiPublicKeyId(), crypto, consts.AppId(), 1000);
    auto provider = std::make_shared<GeneratorJwtProvider>(generator, identity);
    auto verifier = std::make_shared<VirgilCardVerifier>(crypto);

    auto keyPair = crypto->generateKeyPair();

    std::function<std::future<RawSignedModel>(RawSignedModel)> signFunc = [&](RawSignedModel model) {
        std::promise<RawSignedModel> p;
        ModelSigner signer(crypto);
        signer.sign(model, "extra", keyPair.privateKey());
        p.set_value(model);

        return p.get_future();
    };

    auto whitelist = Whitelist({VerifierCredentials("extra", crypto->exportPublicKey(keyPair.publicKey()))});
    verifier->whitelists({whitelist});

    auto cardManager = CardManager(crypto, provider, verifier);
    cardManager.signCallback(signFunc);

    auto keyPair1 = crypto->generateKeyPair();

    auto rawCard = cardManager.generateRawCard(keyPair1.privateKey(), keyPair1.publicKey(), identity);

    auto publishFuture = cardManager.publishCard(rawCard);
    auto publishedCard = publishFuture.get();
    REQUIRE(!publishedCard.isOutdated());
    REQUIRE(publishedCard.signatures().size() == 3);
}

TEST_CASE("test007_STC_34", "[card_manager]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto privateKeyStr = consts.ApiPrivateKey();
    auto privateKeyData = VirgilBase64::decode(privateKeyStr);
    auto privateKey = crypto->importPrivateKey(privateKeyData);

    auto identity = "identity";
    auto generator = JwtGenerator(privateKey, consts.ApiPublicKeyId(), crypto, consts.AppId(), 1000);
    auto provider = std::make_shared<GeneratorJwtProvider>(generator, identity);
    auto verifier = std::make_shared<VirgilCardVerifier>(crypto);
    verifier->verifySelfSignature(false);
    verifier->verifyVirgilSignature(false);

    auto keyPair = crypto->generateKeyPair();

    auto cardManager = CardManager(crypto, provider, verifier);
    auto cardClientStub = std::make_shared<CardClientStub_STC34>();
    cardManager.cardClient(cardClientStub);

    bool errorWasThrown = false;
    try {
        auto future = cardManager.getCard("375f795bf6799b18c4836d33dce5208daf0895a3f7aacbcd0366529aed2345d4");
        auto card = future.get();
    } catch (...) {
        errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);
}

TEST_CASE("test008_STC_35", "[card_manager]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto privateKeyStr = consts.ApiPrivateKey();
    auto privateKeyData = VirgilBase64::decode(privateKeyStr);
    auto privateKey = crypto->importPrivateKey(privateKeyData);

    auto identity = "some_identity";
    auto generator = JwtGenerator(privateKey, consts.ApiPublicKeyId(), crypto, consts.AppId(), 1000);
    auto provider = std::make_shared<GeneratorJwtProvider>(generator, identity);
    auto verifier = std::make_shared<VirgilCardVerifier>(crypto);
    verifier->verifySelfSignature(false);
    verifier->verifyVirgilSignature(false);

    auto cardManager = CardManager(crypto, provider, verifier);
    auto cardClientStub = std::make_shared<CardClientStub_STC34>();
    cardManager.cardClient(cardClientStub);

    auto publicKeyData = VirgilBase64::decode(testData.dict()["STC-34.public_key_base64"]);

    auto rawCardContent = RawCardContent(identity, publicKeyData, time(0));
    auto rawCard1 = RawSignedModel(rawCardContent.snapshot());

    auto privateKeyData1 = VirgilBase64::decode(testData.dict()["STC-34.private_key_base64"]);
    auto privateKey1 = crypto->importPrivateKey(privateKeyData1);
    auto signatureSnapshotData = VirgilBase64::decode(testData.dict()["STC-34.self_signature_snapshot_base64"]);

    ModelSigner signer(crypto);
    signer.selfSign(rawCard1, privateKey1, signatureSnapshotData);

    bool errorWasThrown = false;
    try {
        auto future1 = cardManager.publishCard(rawCard1);
        auto card = future1.get();
    } catch (...) {
        errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);

    auto contentSnapshot = VirgilBase64::decode(testData.dict()["STC-34.content_snapshot_base64"]);
    auto rawCard2 = RawSignedModel(contentSnapshot);
    signer.selfSign(rawCard2, privateKey1);

    errorWasThrown = false;
    try {
        auto future2 = cardManager.publishCard(rawCard2);
        auto card = future2.get();
    } catch (...) {
        errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);
}

TEST_CASE("test009_STC_36", "[card_manager]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();

    auto privateKeyStr = consts.ApiPrivateKey();
    auto privateKeyData = VirgilBase64::decode(privateKeyStr);
    auto privateKey = crypto->importPrivateKey(privateKeyData);

    auto identity = "some_identity";
    auto generator = JwtGenerator(privateKey, consts.ApiPublicKeyId(), crypto, consts.AppId(), 1000);
    auto provider = std::make_shared<GeneratorJwtProvider>(generator, identity);
    auto verifier = std::make_shared<VirgilCardVerifier>(crypto);
    verifier->verifySelfSignature(false);
    verifier->verifyVirgilSignature(false);

    auto cardManager = CardManager(crypto, provider, verifier);
    auto cardClientStub = std::make_shared<CardClientStub_STC34>();
    cardManager.cardClient(cardClientStub);

    bool errorWasThrown = false;
    try {
        auto future = cardManager.searchCards("Alice");
        auto card = future.get();
    } catch (...) {
        errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);
}

TEST_CASE("test0010_STC_26", "[card_manager]") {
    TestConst consts;
    TestUtils utils(consts);
    auto crypto = std::make_shared<Crypto>();
    
    auto privateKeyStr = consts.ApiPrivateKey();
    auto privateKeyData = VirgilBase64::decode(privateKeyStr);
    auto privateKey = crypto->importPrivateKey(privateKeyData);

    auto identity = "some_identity";

    int counter = 0;

    std::function<void(bool forceCallback)> forceCallbackCheck = [&](bool forceCallback) {
        if (counter % 2 == 0)
            REQUIRE(!forceCallback);
        else
            REQUIRE(forceCallback);

        counter++;
    };

    auto provider = std::make_shared<AccessTokenProviderStub_STC26>(identity, forceCallbackCheck);
    auto verifier = std::make_shared<VirgilCardVerifier>(crypto);
    verifier->verifySelfSignature(false);
    verifier->verifyVirgilSignature(false);

    auto cardManager = CardManager(crypto, provider, verifier);

    auto keyPair = crypto->generateKeyPair();

    auto publishFuture = cardManager.publishCard(keyPair.privateKey(), keyPair.publicKey(), identity);
    auto publishedCard = publishFuture.get();

    auto getFuture = cardManager.getCard(publishedCard.identifier());
    auto gotCard = getFuture.get();

    auto searchFuture = cardManager.searchCards(identity);
    auto searchCards = searchFuture.get();
}