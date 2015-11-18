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
 * @file test_public_key_client.cxx
 * @brief Covers "/public-key" endpoint.
 */
#include <string>
#include <memory>
#include <vector>

#include <virgil/sdk/keys/client/KeysClientConnection.h>
#include <virgil/sdk/keys/client/KeysClient.h>
#include <virgil/sdk/keys/http/Request.h>
#include <virgil/sdk/keys/http/Response.h>
#include <virgil/sdk/keys/error/KeysError.h>
#include <virgil/sdk/keys/util/JsonKey.h>
#include <virgil/sdk/keys/model/PublicKey.h>
#include <virgil/sdk/keys/model/UserData.h>
#include <virgil/sdk/keys/model/UserDataClass.h>
#include <virgil/sdk/keys/model/UserDataType.h>
#include <virgil/sdk/keys/io/Marshaller.h>

#include <json.hpp>
#include "fakeit.hpp"

#include "fakeit_helpers.hpp"
#include "helpers.h"

using virgil::sdk::keys::client::KeysClientConnection;
using virgil::sdk::keys::client::KeysClient;
using virgil::sdk::keys::client::Credentials;
using virgil::sdk::keys::client::CredentialsExt;
using virgil::sdk::keys::error::KeysError;
using virgil::sdk::keys::http::Response;
using virgil::sdk::keys::http::Request;
using virgil::sdk::keys::model::PublicKey;
using virgil::sdk::keys::model::UserData;
using virgil::sdk::keys::model::UserDataClass;
using virgil::sdk::keys::model::UserDataType;
using virgil::sdk::keys::io::Marshaller;
using virgil::sdk::keys::util::JsonKey;

using json = nlohmann::json;
using namespace fakeit;

TEST_CASE("Add Public Key (new account) - success", "[virgil-sdk-keys-public-key]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(Marshaller<PublicKey>::toJson(expectedPublicKeyWithUserData(), true));

    auto connectionObj = std::make_shared<KeysClientConnection>(appToken(), KeysClient::kBaseAddressDefault);
    Mock<KeysClientConnection> connection(*connectionObj);
    When(OverloadedMethod(connection, send, Response(const Request&, const Credentials&))).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    Credentials credentials = expectedCredentials();
    PublicKey publicKey = keysClient->publicKey().add(expectedPublicKeyData(),
            {expectedUserData1(), expectedUserData2(), expectedUserData3(), expectedUserData4()},
            credentials);

    Verify(OverloadedMethod(connection, send, Response(const Request&, const Credentials&)));
    checkPublicKeys(publicKey, expectedPublicKeyWithUserData());
}

TEST_CASE("Get Public Key - success", "[virgil-sdk-keys-public-key]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(Marshaller<PublicKey>::toJson(expectedPublicKey()));

    auto connectionObj = std::make_shared<KeysClientConnection>(appToken(), KeysClient::kBaseAddressDefault);
    Mock<KeysClientConnection> connection(*connectionObj);
    When(OverloadedMethod(connection, send, Response(const Request&))).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    PublicKey publicKey = keysClient->publicKey().get(expectedPublicKeyId());

    Verify(OverloadedMethod(connection, send, Response(const Request&)));
    checkPublicKeys(publicKey, expectedPublicKey());
}

TEST_CASE("Update Public Key - success", "[virgil-sdk-keys-public-key]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(Marshaller<PublicKey>::toJson(expectedPublicKey()));

    auto connectionObj = std::make_shared<KeysClientConnection>(appToken(), KeysClient::kBaseAddressDefault);
    Mock<KeysClientConnection> connection(*connectionObj);
    When(OverloadedMethod(connection, send, Response(const Request&, const CredentialsExt&))).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    Credentials newKeyCredentials = expectedCredentials();
    CredentialsExt oldKeyCredentials = expectedCredentialsExt();
    PublicKey publicKey = keysClient->publicKey().update(expectedPublicKeyData(),
            newKeyCredentials, oldKeyCredentials);

    Verify(OverloadedMethod(connection, send, Response(const Request&, const CredentialsExt&)));
    checkPublicKeys(publicKey, expectedPublicKey());
}

TEST_CASE("Delete Public Key - success", "[virgil-sdk-keys-public-key]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body("{}");

    auto connectionObj = std::make_shared<KeysClientConnection>(appToken(), KeysClient::kBaseAddressDefault);
    Mock<KeysClientConnection> connection(*connectionObj);
    When(OverloadedMethod(connection, send, Response(const Request&, const CredentialsExt&))).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    CredentialsExt credentials = expectedCredentialsExt();
    REQUIRE_NOTHROW(keysClient->publicKey().del(credentials));

    Verify(OverloadedMethod(connection, send, Response(const Request&, const CredentialsExt&)));
}

TEST_CASE("Delete Public Key (unsigned) - success", "[virgil-sdk-keys-public-key]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    json payload = {
        { "action_token", "57516f1b-f17c-3154-c91e-edb86c514c5d" },
        { "user_ids", { "test-vs@mailinator.com", "cyber_bob@mailinator.com" } }
    };
    successResponse.body(payload.dump());

    auto connectionObj = std::make_shared<KeysClientConnection>(appToken(), KeysClient::kBaseAddressDefault);
    Mock<KeysClientConnection> connection(*connectionObj);
    When(OverloadedMethod(connection, send, Response(const Request&))).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    std::string responseBody = keysClient->publicKey().del(expectedPublicKeyId());

    Verify(OverloadedMethod(connection, send, Response(const Request&)));
    REQUIRE(responseBody == payload.dump());
}

TEST_CASE("Confirm Delete Public operation - success", "[virgil-sdk-keys-public-key]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body("{}");

    auto connectionObj = std::make_shared<KeysClientConnection>(appToken(), KeysClient::kBaseAddressDefault);
    Mock<KeysClientConnection> connection(*connectionObj);
    When(OverloadedMethod(connection, send, Response(const Request&))).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    REQUIRE_NOTHROW(keysClient->publicKey().confirmDel(expectedPublicKeyId(), actionToken(), confirmationCodes()));

    Verify(OverloadedMethod(connection, send, Response(const Request&)));
}

TEST_CASE("Reset Public Key - success", "[virgil-sdk-keys-public-key]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    json payload = {
        { "action_token", "57516f1b-f17c-3154-c91e-edb86c514c5d" },
        { "user_ids", { "test-vs@mailinator.com", "cyber_bob@mailinator.com" } }
    };
    successResponse.body(payload.dump());

    auto connectionObj = std::make_shared<KeysClientConnection>(appToken(), KeysClient::kBaseAddressDefault);
    Mock<KeysClientConnection> connection(*connectionObj);
    When(OverloadedMethod(connection, send, Response(const Request&, const Credentials&))).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    Credentials credentials(expectedPrivateKeyData());    
    std::string responseBody = keysClient->publicKey().reset(expectedPublicKeyId(),
            expectedPublicKeyData(), credentials);

    Verify(OverloadedMethod(connection, send, Response(const Request&, const Credentials&)));
    REQUIRE(responseBody == payload.dump());
}

TEST_CASE("Confirm Reset Public Key - success", "[virgil-sdk-keys-public-key]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(Marshaller<PublicKey>::toJson(expectedPublicKeyWithUserData(), true));

    auto connectionObj = std::make_shared<KeysClientConnection>(appToken(), KeysClient::kBaseAddressDefault);
    Mock<KeysClientConnection> connection(*connectionObj);
    When(OverloadedMethod(connection, send, Response(const Request&, const Credentials&))).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    Credentials credentials = expectedCredentials();
    PublicKey publicKey = keysClient->publicKey().confirmReset(expectedPublicKeyId(), credentials, actionToken(),
            confirmationCodes());

    Verify(OverloadedMethod(connection, send, Response(const Request&, const Credentials&)));
    checkPublicKeys(publicKey, expectedPublicKeyWithUserData());
}

TEST_CASE("Grab Public Key by UDID - success", "[virgil-sdk-keys-public-key]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(Marshaller<PublicKey>::toJson(expectedPublicKey()));

    auto connectionObj = std::make_shared<KeysClientConnection>(appToken(), KeysClient::kBaseAddressDefault);
    Mock<KeysClientConnection> connection(*connectionObj);
    When(OverloadedMethod(connection, send, Response(const Request&))).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    PublicKey publicKey = keysClient->publicKey().grab("user@virgilsecurity.com");

    Verify(OverloadedMethod(connection, send, Response(const Request&)));
    checkPublicKeys(publicKey, expectedPublicKey());
}

TEST_CASE("Grab Public Key by credentials - success", "[virgil-sdk-keys-public-key]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    successResponse.body(Marshaller<PublicKey>::toJson(expectedPublicKeyWithUserData(), true));

    auto connectionObj = std::make_shared<KeysClientConnection>(appToken(), KeysClient::kBaseAddressDefault);
    Mock<KeysClientConnection> connection(*connectionObj);
    When(OverloadedMethod(connection, send, Response(const Request&, const CredentialsExt&))).Return(successResponse);

    auto keysClient = std::make_shared<KeysClient>(make_moc_shared(connection));
    CredentialsExt credentials = expectedCredentialsExt();
    PublicKey publicKey = keysClient->publicKey().grab(credentials);

    Verify(OverloadedMethod(connection, send, Response(const Request&, const CredentialsExt&)));
    checkPublicKeys(publicKey, expectedPublicKeyWithUserData());
}
