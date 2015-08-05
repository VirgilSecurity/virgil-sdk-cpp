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
 * @file test_user_data_client.cxx
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

#include <virgil/sdk/keys/client/KeysClient.h>
using virgil::sdk::keys::client::KeysClient;

#include <virgil/sdk/keys/error/KeysError.h>
using virgil::sdk::keys::error::KeysError;

#include <virgil/sdk/keys/util/Base64.h>
using virgil::sdk::keys::util::Base64;
#include <virgil/sdk/keys/util/JsonKey.h>
using virgil::sdk::keys::util::JsonKey;

#include <virgil/sdk/keys/model/PublicKey.h>
using virgil::sdk::keys::model::PublicKey;
#include <virgil/sdk/keys/model/UserData.h>
using virgil::sdk::keys::model::UserData;

#include "fakeit_utils.hpp"

static const std::string expectedAccountId = "3a768eea-cbda-4926-a82d-831cb89092aa";
static const std::string expectedPublicKeyId = "17084b40-08f5-4bcd-a739-c0d08c176bad";
static const std::string expectedUserDataId = "e33898de-6302-4756-8f0c-5f6c5218e02e";
static const std::vector<unsigned char> expectedPublicKey {'t','e','s','t'};
static const std::string expectedClassName = "user_id";
static const std::string expectedType = "email";
static const std::string expectedValue = "test@virgilsecurity.com";
static const std::string appToken = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
static const std::string guid = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

TEST_CASE("Add User Data - success", "[virgil-sdk-keys-user-data]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(json({
        {JsonKey::id, {
            {JsonKey::accountId, expectedAccountId},
            {JsonKey::publicKeyId, expectedPublicKeyId},
            {JsonKey::userDataId, expectedUserDataId},
        }},
        {JsonKey::className, expectedClassName},
        {JsonKey::type, expectedType},
        {JsonKey::value, expectedValue}
    }).dump());

    auto connectionObj = std::make_shared<Connection>(appToken);
    Mock<ConnectionBase> connection(*connectionObj);
    When(Method(connection, send)).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    UserData userData =
            keysClient->userData().add(expectedPublicKeyId, expectedClassName, expectedType, expectedValue, guid);

    Verify(Method(connection, send));
    REQUIRE(userData.accountId() == expectedAccountId);
    REQUIRE(userData.publicKeyId() == expectedPublicKeyId);
    REQUIRE(userData.userDataId() == expectedUserDataId);
    REQUIRE(userData.className() == expectedClassName);
    REQUIRE(userData.type() == expectedType);
    REQUIRE(userData.value() == expectedValue);
}

TEST_CASE("Get User Data - success", "[virgil-sdk-keys-user-data]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(json({
        {JsonKey::id, {
            {JsonKey::accountId, expectedAccountId},
            {JsonKey::publicKeyId, expectedPublicKeyId},
            {JsonKey::userDataId, expectedUserDataId},
        }},
        {JsonKey::className, expectedClassName},
        {JsonKey::type, expectedType},
        {JsonKey::value, expectedValue}
    }).dump());

    auto connectionObj = std::make_shared<Connection>(appToken);
    Mock<ConnectionBase> connection(*connectionObj);
    When(Method(connection, send)).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    UserData userData = keysClient->userData().get(expectedUserDataId);

    Verify(Method(connection, send));
    REQUIRE(userData.accountId() == expectedAccountId);
    REQUIRE(userData.publicKeyId() == expectedPublicKeyId);
    REQUIRE(userData.userDataId() == expectedUserDataId);
    REQUIRE(userData.className() == expectedClassName);
    REQUIRE(userData.type() == expectedType);
    REQUIRE(userData.value() == expectedValue);
}

TEST_CASE("Confirm User Data - success", "[virgil-sdk-keys-user-data]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(json::object().dump());

    auto connectionObj = std::make_shared<Connection>(appToken);
    Mock<ConnectionBase> connection(*connectionObj);
    When(Method(connection, send)).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    REQUIRE_NOTHROW(keysClient->userData().confirm(expectedUserDataId, "F9U0W9", guid));
    Verify(Method(connection, send));
}

TEST_CASE("Resend User Data Confirmation - success", "[virgil-sdk-keys-user-data]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(json::object().dump());

    auto connectionObj = std::make_shared<Connection>(appToken);
    Mock<ConnectionBase> connection(*connectionObj);
    When(Method(connection, send)).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    REQUIRE_NOTHROW(keysClient->userData().resendConfirmation(expectedUserDataId, guid));
    Verify(Method(connection, send));
}

TEST_CASE("Search User Data - success", "[virgil-sdk-keys-user-data]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(json::array({
        {
            {JsonKey::id, {
                {JsonKey::accountId, expectedAccountId},
                {JsonKey::publicKeyId, expectedPublicKeyId},
                {JsonKey::userDataId, expectedUserDataId},
            }},
            {JsonKey::className, expectedClassName},
            {JsonKey::type, expectedType},
            {JsonKey::value, expectedValue}
        }
    }).dump());

    auto connectionObj = std::make_shared<Connection>(appToken);
    Mock<ConnectionBase> connection(*connectionObj);
    When(Method(connection, send)).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    std::vector<UserData> allUserData = keysClient->userData().search(expectedValue);

    Verify(Method(connection, send));
    REQUIRE(allUserData.size() == 1);

    UserData userData = allUserData.front();
    REQUIRE(userData.accountId() == expectedAccountId);
    REQUIRE(userData.publicKeyId() == expectedPublicKeyId);
    REQUIRE(userData.userDataId() == expectedUserDataId);
    REQUIRE(userData.className() == expectedClassName);
    REQUIRE(userData.type() == expectedType);
    REQUIRE(userData.value() == expectedValue);
}

TEST_CASE("Search User Data and Expand Key - success", "[virgil-sdk-keys-user-data]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(json::array({
        {
            {JsonKey::id, {
                {JsonKey::accountId, expectedAccountId},
                {JsonKey::publicKeyId, expectedPublicKeyId},
                {JsonKey::userDataId, expectedUserDataId},
            }},
            {JsonKey::className, expectedClassName},
            {JsonKey::type, expectedType},
            {JsonKey::value, expectedValue},
            {JsonKey::expanded, {
                {JsonKey::publicKey, {
                    {JsonKey::id, {
                        {JsonKey::accountId, expectedAccountId},
                        {JsonKey::publicKeyId, expectedPublicKeyId},
                    }},
                    {JsonKey::publicKey, Base64::encode(expectedPublicKey)}
                }}
            }}
        }
    }).dump(4));

    auto connectionObj = std::make_shared<Connection>(appToken);
    Mock<ConnectionBase> connection(*connectionObj);
    When(Method(connection, send)).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    std::vector<UserData> allUserData = keysClient->userData().search(expectedValue, true);

    Verify(Method(connection, send));
    REQUIRE(allUserData.size() == 1);

    UserData userData = allUserData.front();
    REQUIRE(userData.accountId() == expectedAccountId);
    REQUIRE(userData.publicKeyId() == expectedPublicKeyId);
    REQUIRE(userData.userDataId() == expectedUserDataId);
    REQUIRE(userData.className() == expectedClassName);
    REQUIRE(userData.type() == expectedType);
    REQUIRE(userData.value() == expectedValue);
    REQUIRE(userData.publicKey());
    REQUIRE(userData.publicKey()->accountId() == expectedAccountId);
    REQUIRE(userData.publicKey()->publicKeyId() == expectedPublicKeyId);
    REQUIRE(userData.publicKey()->key() == expectedPublicKey);
}
