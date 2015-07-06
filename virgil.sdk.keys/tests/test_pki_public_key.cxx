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
 * @file test_pki_public_key.cxx
 * @brief Covers "/public-key" endpoint.
 */
#include <string>
#include <memory>
#include <vector>
#include <algorithm>

#include <json.hpp>
using json = nlohmann::json;

#include "fakeit.hpp"
using namespace fakeit;

#include <virgil/sdk/keys/http/Connection.h>
using virgil::sdk::keys::http::Connection;
#include <virgil/sdk/keys/http/ConnectionBase.h>
using virgil::sdk::keys::http::ConnectionBase;

#include <virgil/sdk/keys/client/PkiClientBase.h>
using virgil::sdk::keys::client::PkiClientBase;

#include <virgil/sdk/keys/error/PkiError.h>
using virgil::sdk::keys::error::PkiError;

#include <virgil/sdk/keys/util/Base64.h>
using virgil::sdk::keys::util::Base64;
#include <virgil/sdk/keys/util/JsonKey.h>
using virgil::sdk::keys::util::JsonKey;

#include <virgil/sdk/keys/model/UserData.h>
using virgil::sdk::keys::model::UserData;
#include <virgil/sdk/keys/model/UserDataClass.h>
using virgil::sdk::keys::model::UserDataClass;
#include <virgil/sdk/keys/model/UserDataType.h>
using virgil::sdk::keys::model::UserDataType;

#include "fakeit_utils.hpp"

static const std::string appToken = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

TEST_CASE("Add Public Key (new account) - success", "[pki-public-key]") {
    auto expectedAccountId = "3a768eea-cbda-4926-a82d-831cb89092aa";
    auto expectedPublicKeyId = "17084b40-08f5-4bcd-a739-c0d08c176bad";
    std::vector<unsigned char> expectedPublicKey {'t','e','s','t'};

    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(json({
        {JsonKey::id, {
            {JsonKey::accountId, expectedAccountId},
            {JsonKey::publicKeyId, expectedPublicKeyId},
        }},
        {JsonKey::publicKey, Base64::encode(expectedPublicKey)},
        {JsonKey::userData, json::array()}
    }).dump());

    UserData userData = UserData::email("test@test.com");

    auto connectionObj = std::make_shared<ConnectionBase>(appToken);
    Mock<Connection> connection(*connectionObj);
    When(Method(connection, send)).Return(successResponse);

    auto pkiClient = std::make_shared<PkiClientBase>(make_moc_shared(connection));
    PublicKey publicKey = pkiClient->publicKey().add(expectedPublicKey, {userData});

    Verify(Method(connection, send));
    REQUIRE(publicKey.accountId() == expectedAccountId);
    REQUIRE(publicKey.publicKeyId() == expectedPublicKeyId);
    REQUIRE(publicKey.key() == expectedPublicKey);
}

TEST_CASE("Add Public Key (new account) - failed", "[pki-public-key]") {
    std::vector<unsigned char> expectedPublicKey {'t','e','s','t'};

    Response errorResponse = Response().statusCode(Response::StatusCode::REQUEST_ERROR).contentType("application/json");
    errorResponse.body(json({
        {JsonKey::error, {
            {JsonKey::code, 20103 /* Public key must be base64-encoded string */},
        }}
    }).dump());

    auto connectionObj = std::make_shared<ConnectionBase>(appToken);
    Mock<Connection> connection(*connectionObj);
    When(Method(connection, send)).Return(errorResponse);

    auto pkiClient = std::make_shared<PkiClientBase>(make_moc_shared(connection));
    REQUIRE_THROWS_AS(pkiClient->publicKey().add(expectedPublicKey, {UserData()}), PkiError);

    Verify(Method(connection, send));
}

TEST_CASE("Get Public Key - success", "[pki-public-key]") {
    auto expectedAccountId = "3a768eea-cbda-4926-a82d-831cb89092aa";
    auto expectedPublicKeyId = "17084b40-08f5-4bcd-a739-c0d08c176bad";
    std::vector<unsigned char> expectedPublicKey {'t','e','s','t'};
    std::vector<UserData> expectedUserData {
        UserData::phone("+1 123 777 7777").isConfirmed(false),
        UserData::email("test@virgilsecurity.com").isConfirmed(true)
    };

    json successResponseJson = {
        {JsonKey::id, {
            {JsonKey::accountId, expectedAccountId},
            {JsonKey::publicKeyId, expectedPublicKeyId},
        }},
        {JsonKey::publicKey, Base64::encode(expectedPublicKey)},
        {JsonKey::userData, json::array()}
    };
    for (auto userData : expectedUserData) {
        successResponseJson[JsonKey::userData].push_back(json({
            {JsonKey::className, userData.className()},
            {JsonKey::type, userData.type()},
            {JsonKey::value, userData.value()},
            {JsonKey::isConfirmed, userData.isConfirmed()}
        }));
    }

    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(successResponseJson.dump());

    auto connectionObj = std::make_shared<ConnectionBase>(appToken);
    Mock<Connection> connection(*connectionObj);
    When(Method(connection, send)).Return(successResponse);

    auto pkiClient = std::make_shared<PkiClientBase>(make_moc_shared(connection));
    PublicKey publicKey = pkiClient->publicKey().get(expectedPublicKeyId);

    Verify(Method(connection, send));
    REQUIRE(publicKey.accountId() == expectedAccountId);
    REQUIRE(publicKey.publicKeyId() == expectedPublicKeyId);
    REQUIRE(publicKey.key() == expectedPublicKey);
    REQUIRE(publicKey.userData().size() == expectedUserData.size());
    for (auto expected : expectedUserData) {
        auto userData = publicKey.userData();
        bool found = std::find(userData.begin(), userData.end(), expected) != userData.end();
        REQUIRE(found == true);
    }
}

TEST_CASE ("Search Public Key - success", "[pki-public-key]") {
    auto expectedAccountId = "3a768eea-cbda-4926-a82d-831cb89092aa";
    auto expectedPublicKeyId = "17084b40-08f5-4bcd-a739-c0d08c176bad";
    std::vector<unsigned char> expectedPublicKey {'t','e','s','t'};
    json successResponseJson = json::array({
        {
            {JsonKey::id, {
                {JsonKey::accountId, expectedAccountId},
            }},
            {JsonKey::publicKeys, json::array({
                {
                    {JsonKey::id, {
                        {JsonKey::accountId, expectedAccountId},
                        {JsonKey::publicKeyId, expectedPublicKeyId},
                    }},
                    {JsonKey::publicKey, Base64::encode(expectedPublicKey)}
                }
            })}
        }
    });

    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(successResponseJson.dump());

    auto connectionObj = std::make_shared<ConnectionBase>(appToken);
    Mock<Connection> connection(*connectionObj);
    When(Method(connection, send)).Return(successResponse);

    auto pkiClient = std::make_shared<PkiClientBase>(make_moc_shared(connection));
    std::vector<PublicKey> publicKeys =
            pkiClient->publicKey().search("test@virgilsecurity.com", UserDataType::emailId);

    Verify(Method(connection, send));

    REQUIRE(publicKeys.size() == 1);
    PublicKey publicKey = publicKeys.front();
    REQUIRE(publicKey.accountId() == expectedAccountId);
    REQUIRE(publicKey.publicKeyId() == expectedPublicKeyId);
    REQUIRE(publicKey.key() == expectedPublicKey);
}
