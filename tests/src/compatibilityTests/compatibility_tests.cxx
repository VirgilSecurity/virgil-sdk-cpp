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
#include <TestData.h>

#include <virgil/sdk/cards/CardManager.h>
#include <virgil/sdk/cards/verification/VirgilCardVerifier.h>
#include <virgil/sdk/util/JsonUtils.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/jwt/JwtVerifier.h>
#include <virgil/sdk/jwt/JwtGenerator.h>

using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestUtils;
using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::VirgilBase64;
using virgil::sdk::cards::CardManager;
using virgil::sdk::cards::verification::VirgilCardVerifier;
using virgil::sdk::client::models::RawCardContent;
using nlohmann::json;
using virgil::sdk::util::JsonKey;
using virgil::sdk::jwt::JwtVerifier;
using virgil::sdk::jwt::Jwt;
using virgil::sdk::jwt::JwtGenerator;
using virgil::sdk::cards::verification::Whitelist;

const auto testData = virgil::sdk::test::TestData();

TEST_CASE("test001_STC_1", "[compatibility]") {
    TestConst consts;
    TestUtils utils(consts);

    auto rawCardString = testData.dict()["STC-1.as_string"];
    auto rawCard1 = RawSignedModel::importFromBase64EncodedString(rawCardString);

    auto rawCardJson = testData.dict()["STC-1.as_json"];
    auto rawCard2 = RawSignedModel::importFromJson(rawCardJson);

    auto rawCardContent1 = RawCardContent::parse(rawCard1.contentSnapshot());
    auto rawCardContent2 = RawCardContent::parse(rawCard2.contentSnapshot());

    REQUIRE(rawCardContent1.identity() == "test");
    REQUIRE(VirgilBase64::encode(rawCardContent1.publicKey()) == "MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk=");
    REQUIRE(rawCardContent1.version() == "5.0");
    REQUIRE(rawCardContent1.createdAt() == 1515686245);
    REQUIRE(rawCardContent1.previousCardId().empty());
    REQUIRE(rawCard1.signatures().empty());

    REQUIRE(utils.isRawCardContentEqual(rawCardContent1, rawCardContent2));
    REQUIRE(rawCard2.signatures().empty());

    auto newRawCard = RawSignedModel(rawCardContent1.snapshot());
    REQUIRE(newRawCard.contentSnapshot() == rawCard1.contentSnapshot());

    auto exportedRawCard1AsJson = newRawCard.exportAsJson();
    auto exportedRawCard1AsString = newRawCard.exportAsBase64EncodedString();
    REQUIRE(exportedRawCard1AsJson == rawCardJson);
    REQUIRE(exportedRawCard1AsString == rawCardString);

    auto importedRawCardContent1 = RawCardContent::parse(rawCardContent1.snapshot());
    REQUIRE(importedRawCardContent1.previousCardId().empty());
}

TEST_CASE("test002_STC_2", "[compatibility]") {
    TestConst consts;
    TestUtils utils(consts);

    auto rawCardString = testData.dict()["STC-2.as_string"];
    auto rawCard1 = RawSignedModel::importFromBase64EncodedString(rawCardString);

    auto rawCardJson = testData.dict()["STC-2.as_json"];
    auto rawCard2 = RawSignedModel::importFromJson(rawCardJson);

    auto rawCardContent1 = RawCardContent::parse(rawCard1.contentSnapshot());
    auto rawCardContent2 = RawCardContent::parse(rawCard2.contentSnapshot());

    REQUIRE(rawCardContent1.identity() == "test");
    REQUIRE(VirgilBase64::encode(rawCardContent1.publicKey()) == "MCowBQYDK2VwAyEA6d9bQQFuEnU8vSmx9fDo0Wxec42JdNg4VR4FOr4/BUk=");
    REQUIRE(rawCardContent1.version() == "5.0");
    REQUIRE(rawCardContent1.createdAt() == 1515686245);
    REQUIRE(rawCardContent1.previousCardId() == "a666318071274adb738af3f67b8c7ec29d954de2cabfd71a942e6ea38e59fff9");
    REQUIRE(rawCard1.signatures().size() == 3);

    for (auto& signature : rawCard1.signatures()) {
        if (signature.signer() == "self") {
            REQUIRE(VirgilBase64 ::encode(signature.signature()) == "MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8=");
            REQUIRE(signature.snapshot().empty());
        } else if (signature.signer() == "virgil") {
            REQUIRE(VirgilBase64 ::encode(signature.signature()) == "MFEwDQYJYIZIAWUDBAIDBQAEQNXguibY1cDCfnuJhTK+jX/Qv6v5i5TzqQs3e1fWlbisdUWYh+s10gsLkhf83wOqrm8ZXUCpjgkJn83TDaKYZQ8=");
            REQUIRE(signature.snapshot().empty());
        } else if (signature.signer() == "extra") {
            REQUIRE(VirgilBase64 ::encode(signature.signature()) == "MFEwDQYJYIZIAWUDBAIDBQAEQCA3O35Rk+doRPHkHhJJKJyFxz2APDZOSBZi6QhmI7BP3yTb65gRYwu0HtNNYdMRsEqVj9IEKhtDelf4SKpbJwo=");
            REQUIRE(signature.snapshot().empty());
        } else {
            FAIL();
        }
    }

    REQUIRE(utils.isRawCardContentEqual(rawCardContent1, rawCardContent2));
    REQUIRE(utils.isRawSignaturesEqual(rawCard1.signatures(), rawCard2.signatures()));

    REQUIRE(rawCard1.exportAsBase64EncodedString() == rawCardString);
    REQUIRE(rawCard1.exportAsJson() == rawCardJson);
}

TEST_CASE("test003_STC_3", "[compatibility]") {
    TestConst consts;
    TestUtils utils(consts);

    auto verifier = std::make_shared<VirgilCardVerifier>(utils.crypto(), std::vector<Whitelist>(), false, false);

    CardManager cardManager(utils.crypto(), nullptr, verifier);

    auto rawCardString = testData.dict()["STC-3.as_string"];
    auto card1 = cardManager.importCardFromBase64(rawCardString);

    auto rawCardJson = testData.dict()["STC-3.as_json"];
    auto card2 = cardManager.importCardFromJson(rawCardJson);

    REQUIRE(card1.identifier() == testData.dict()["STC-3.card_id"]);
    REQUIRE(card1.identity() == "test");
    auto publicKeyData = utils.crypto()->exportPublicKey(card1.publicKey());
    REQUIRE(VirgilBase64::encode(publicKeyData) == testData.dict()["STC-3.public_key_base64"]);
    REQUIRE(card1.version() == "5.0");
    REQUIRE(card1.createdAt() == 1515686245);
    REQUIRE(card1.previousCardId().empty());
    REQUIRE(card1.previousCard() == nullptr);
    REQUIRE(card1.signatures().empty());

    REQUIRE(utils.isCardsEqual(card1, card2));
    REQUIRE(utils.isCardSignaturesEqual(card1.signatures(), card2.signatures()));

    auto exportedCardBase64 = cardManager.exportCardAsBase64(card1);
    auto exportedCardJson = cardManager.exportCardAsJson(card1);
    REQUIRE(rawCardString == exportedCardBase64);
    REQUIRE(rawCardJson == exportedCardJson);
}

TEST_CASE("test004_STC_4", "[compatibility]") {
    TestConst consts;
    TestUtils utils(consts);

    auto verifier = std::make_shared<VirgilCardVerifier>(utils.crypto(), std::vector<Whitelist>(), false, false);

    CardManager cardManager(utils.crypto(), nullptr, verifier);

    auto rawCardString = testData.dict()["STC-4.as_string"];
    auto card1 = cardManager.importCardFromBase64(rawCardString);

    auto rawCardJson = testData.dict()["STC-4.as_json"];
    auto card2 = cardManager.importCardFromJson(rawCardJson);

    REQUIRE(card1.identifier() == testData.dict()["STC-4.card_id"]);
    REQUIRE(card1.identity() == "test");
    auto publicKeyData = utils.crypto()->exportPublicKey(card1.publicKey());
    REQUIRE(VirgilBase64::encode(publicKeyData) == testData.dict()["STC-4.public_key_base64"]);
    REQUIRE(card1.version() == "5.0");
    REQUIRE(card1.createdAt() == 1515686245);
    REQUIRE(card1.previousCardId().empty());
    REQUIRE(card1.previousCard() == nullptr);
    REQUIRE(card1.signatures().size() == 3);

    for (auto& signature : card1.signatures()) {
        if (signature.signer() == "self") {
            REQUIRE(VirgilBase64 ::encode(signature.signature()) == testData.dict()["STC-4.signature_self_base64"]);
            REQUIRE(signature.snapshot().empty());
            REQUIRE(signature.extraFields().empty());
        } else if (signature.signer() == "virgil") {
            REQUIRE(VirgilBase64 ::encode(signature.signature()) == testData.dict()["STC-4.signature_virgil_base64"]);
            REQUIRE(signature.snapshot().empty());
            REQUIRE(signature.extraFields().empty());
        } else if (signature.signer() == "extra") {
            REQUIRE(VirgilBase64 ::encode(signature.signature()) == testData.dict()["STC-4.signature_extra_base64"]);
            REQUIRE(signature.snapshot().empty());
            REQUIRE(signature.extraFields().empty());
        } else {
            FAIL();
        }
    }

    REQUIRE(utils.isCardsEqual(card1, card2));
    REQUIRE(utils.isCardSignaturesEqual(card1.signatures(), card2.signatures()));

    auto exportedCardBase64 = cardManager.exportCardAsBase64(card1);
    auto exportedCardJson = cardManager.exportCardAsJson(card1);
    REQUIRE(rawCardString == exportedCardBase64);
    REQUIRE(rawCardJson == exportedCardJson);
}

TEST_CASE("test005_STC_22", "[compatibility]") {
    auto crypto = std::make_shared<Crypto>();

    auto apiPublicKeyBase64 = testData.dict()["STC-22.api_public_key_base64"];
    auto apiPublicKeyId = testData.dict()["STC-22.api_key_id"];
    auto apiPublicKeyData = VirgilBase64::decode(apiPublicKeyBase64);
    auto apiPubicKey = crypto->importPublicKey(apiPublicKeyData);

    auto jwtVerifier = JwtVerifier(apiPubicKey, apiPublicKeyId, crypto);

    auto jwtStringRepresentation = testData.dict()["STC-22.jwt"];
    auto jwt = Jwt::parse(jwtStringRepresentation);

    auto keyIdentifier = testData.dict()["STC-22.api_key_id"];
    REQUIRE(jwt.headerContent().algorithm() == "VEDS512");
    REQUIRE(jwt.headerContent().contentType() == "virgil-jwt;v=1");
    REQUIRE(jwt.headerContent().type() == "JWT");
    REQUIRE(jwt.headerContent().keyIdentifier() == keyIdentifier);

    REQUIRE(jwt.bodyContent().identity() == "some_identity");
    REQUIRE(jwt.bodyContent().appId() == "13497c3c795e3a6c32643b0a76957b70d2332080762469cdbec89d6390e6dbd7");
    REQUIRE(jwt.bodyContent().issuedAt() == 1518513309);
    REQUIRE(jwt.bodyContent().expiresAt() == 1518513909);
    REQUIRE(jwt.isExpired());

    REQUIRE(jwt.stringRepresentation() == jwtStringRepresentation);

    std::unordered_map<std::string, std::string> dic = {
            {"username", "some_username"}
    };
    REQUIRE(jwt.bodyContent().additionalData() == dic);
    REQUIRE(jwtVerifier.verifyToken(jwt));
}

TEST_CASE("test006_STC_23", "[compatibility]") {
    auto crypto = std::make_shared<Crypto>();

    auto apiPublicKeyBase64 = testData.dict()["STC-23.api_public_key_base64"];
    auto apiPublicKeyId = testData.dict()["STC-23.api_key_id"];
    auto apiPublicKeyData = VirgilBase64::decode(apiPublicKeyBase64);
    auto apiPubicKey = crypto->importPublicKey(apiPublicKeyData);

    auto apiPrivateKeyBase64 = testData.dict()["STC-23.api_private_key_base64"];
    auto appId = testData.dict()["STC-23.app_id"];
    auto apiPrivateKeyData = VirgilBase64::decode(apiPrivateKeyBase64);
    auto apiPrivateKey = crypto->importPrivateKey(apiPrivateKeyData);

    auto jwtVerifier = JwtVerifier(apiPubicKey, apiPublicKeyId, crypto);

    auto generator = JwtGenerator(apiPrivateKey, apiPublicKeyId, crypto, appId, 1000);

    auto identity = "some_identity";
    std::unordered_map<std::string, std::string> dic = {
            {"username", "some_username"}
    };

    auto jwt = generator.generateToken(identity, dic);

    auto keyIdentifier = testData.dict()["STC-23.api_key_id"];
    REQUIRE(jwt.headerContent().algorithm() == "VEDS512");
    REQUIRE(jwt.headerContent().contentType() == "virgil-jwt;v=1");
    REQUIRE(jwt.headerContent().type() == "JWT");
    REQUIRE(jwt.headerContent().keyIdentifier() == keyIdentifier);

    REQUIRE(jwt.bodyContent().identity() == "some_identity");
    REQUIRE(jwt.bodyContent().appId() == "13497c3c795e3a6c32643b0a76957b70d2332080762469cdbec89d6390e6dbd7");
    REQUIRE(!jwt.isExpired());
    REQUIRE(jwt.bodyContent().additionalData() == dic);

    REQUIRE(jwtVerifier.verifyToken(jwt));
}