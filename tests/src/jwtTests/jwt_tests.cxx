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
#include <chrono>

#include <TestData.h>

#include <virgil/sdk/jwt/providers/GeneratorJwtProvider.h>
#include <virgil/sdk/jwt/providers/CallbackJwtProvider.h>
#include <virgil/sdk/jwt/providers/ConstAccessTokenProvider.h>
#include <virgil/sdk/util/JsonUtils.h>

using virgil::sdk::crypto::Crypto;
using virgil::sdk::VirgilBase64;
using virgil::sdk::jwt::JwtGenerator;
using virgil::sdk::jwt::providers::CallbackJwtProvider;
using virgil::sdk::jwt::providers::ConstAccessTokenProvider;
using virgil::sdk::jwt::TokenContext;
using virgil::sdk::jwt::Jwt;
using virgil::sdk::util::JsonUtils;

const auto testData = virgil::sdk::test::TestData();

TEST_CASE("test001_STC_24", "[card_manager]") {
    auto crypto = std::make_shared<Crypto>();

    std::function<std::future<std::string>(const TokenContext&)> callback = [&](const TokenContext& tokenContext) {
        std::promise<std::string> p;

        auto keyPair = crypto->generateKeyPair();
        auto generator = JwtGenerator(keyPair.privateKey(), "id", crypto, "appId", 10);
        auto jwt = generator.generateToken(tokenContext.identity());
        p.set_value(jwt.stringRepresentation());

        return p.get_future();
    };
    auto callbackProvider = CallbackJwtProvider(callback);

    auto tokenContext = TokenContext("test", "some_identity");
    auto futureToken1 = callbackProvider.getToken(tokenContext);
    auto token1 = futureToken1.get();

    auto futureToken2 = callbackProvider.getToken(tokenContext);
    auto token2 = futureToken2.get();

    REQUIRE(token1 != token2);

    std::function<std::future<std::string>(const TokenContext&)> invalidCallback = [&](const TokenContext& tokenContext) {
        std::promise<std::string> p;
        p.set_value("invalid-token");

        return p.get_future();
    };
    auto callbackInvalidProvider = CallbackJwtProvider(invalidCallback);

    bool errorWasThrown = false;
    try {
        auto futureToken3 = callbackInvalidProvider.getToken(tokenContext);
        auto token3 = futureToken3.get();
    } catch (...) {
        errorWasThrown = true;
    }
    REQUIRE(errorWasThrown);
}

TEST_CASE("test001_STC_37", "[card_manager]") {
    auto crypto = std::make_shared<Crypto>();

    auto keyPair = crypto->generateKeyPair();

    auto ttl = 1;
    auto generator = JwtGenerator(keyPair.privateKey(), "id", crypto, "appId", ttl);
    auto token = generator.generateToken("some_identity");
    auto constProvider = ConstAccessTokenProvider(std::make_shared<Jwt>(token));

    auto tokenContext = TokenContext("test");
    auto futureToken1 = constProvider.getToken(tokenContext);
    auto token1 = futureToken1.get();

    std::this_thread::sleep_for(std::chrono::seconds(ttl));

    auto futureToken2 = constProvider.getToken(tokenContext);
    auto token2 = futureToken2.get();

    REQUIRE(token1 == token2);
}

TEST_CASE("test001_STC_28", "[card_manager]") {
    auto tokenStr = testData.dict()["STC-28.jwt"];
    auto jwt = Jwt::parse(tokenStr);

    REQUIRE(jwt.headerContent().algorithm() == testData.dict()["STC-28.jwt_algorithm"]);
    REQUIRE(jwt.headerContent().contentType() == testData.dict()["STC-28.jwt_content_type"]);
    REQUIRE(jwt.headerContent().type() == testData.dict()["STC-28.jwt_type"]);
    REQUIRE(jwt.headerContent().keyIdentifier() == testData.dict()["STC-28.jwt_api_key_id"]);

    REQUIRE(jwt.bodyContent().identity() == testData.dict()["STC-28.jwt_identity"]);
    REQUIRE(jwt.bodyContent().appId() == testData.dict()["STC-28.jwt_app_id"]);
    std::string issuedAt = testData.dict()["STC-28.jwt_issued_at"];
    REQUIRE(std::to_string(jwt.bodyContent().issuedAt()) == issuedAt);
    std::string expiresAt = testData.dict()["STC-28.jwt_expires_at"];
    REQUIRE(std::to_string(jwt.bodyContent().expiresAt()) == expiresAt);

    REQUIRE(jwt.isExpired());
    std::string addData = testData.dict()["STC-28.jwt_additional_data"];
    auto map = JsonUtils::jsonToUnorderedMap(nlohmann::json::parse(addData));
    REQUIRE(jwt.bodyContent().additionalData() == map);
    auto signatureStr = VirgilBase64::encode(jwt.signatureContent());
    REQUIRE(signatureStr == testData.dict()["STC-28.jwt_signature_base64"]);

    REQUIRE(jwt.stringRepresentation() == tokenStr);
}

TEST_CASE("test001_STC_29", "[card_manager]") {
    auto tokenStr = testData.dict()["STC-29.jwt"];
    auto jwt = Jwt::parse(tokenStr);

    REQUIRE(jwt.headerContent().algorithm() == testData.dict()["STC-29.jwt_algorithm"]);
    REQUIRE(jwt.headerContent().contentType() == testData.dict()["STC-29.jwt_content_type"]);
    REQUIRE(jwt.headerContent().type() == testData.dict()["STC-29.jwt_type"]);
    REQUIRE(jwt.headerContent().keyIdentifier() == testData.dict()["STC-29.jwt_api_key_id"]);

    REQUIRE(jwt.bodyContent().identity() == testData.dict()["STC-29.jwt_identity"]);
    REQUIRE(jwt.bodyContent().appId() == testData.dict()["STC-29.jwt_app_id"]);
    std::string issuedAt = testData.dict()["STC-29.jwt_issued_at"];
    REQUIRE(std::to_string(jwt.bodyContent().issuedAt()) == issuedAt);
    std::string expiresAt = testData.dict()["STC-29.jwt_expires_at"];
    REQUIRE(std::to_string(jwt.bodyContent().expiresAt()) == expiresAt);

    REQUIRE(!jwt.isExpired());
    std::string addData = testData.dict()["STC-29.jwt_additional_data"];
    auto map = JsonUtils::jsonToUnorderedMap(nlohmann::json::parse(addData));
    REQUIRE(jwt.bodyContent().additionalData() == map);
    auto signatureStr = VirgilBase64::encode(jwt.signatureContent());
    REQUIRE(signatureStr == testData.dict()["STC-29.jwt_signature_base64"]);

    REQUIRE(jwt.stringRepresentation() == tokenStr);
}