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

#include <memory>

#include "fakeit.hpp"

#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/privatekeys//client/KeysClientConnection.h>
#include <virgil/sdk/privatekeys/client/PrivateKeysClient.h>
#include <virgil/sdk/privatekeys/http/Request.h>
#include <virgil/sdk/privatekeys/http/Response.h>
#include <virgil/sdk/privatekeys/model/PrivateKey.h>

#include "helpers.h"
#include "fakeit_helpers.hpp"

using namespace fakeit;

using json = nlohmann::json;

using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::privatekeys::client::Credentials;
using virgil::sdk::privatekeys::client::KeysClientConnection;
using virgil::sdk::privatekeys::client::PrivateKeysClient;
using virgil::sdk::privatekeys::http::Request;
using virgil::sdk::privatekeys::http::Response;
using virgil::sdk::privatekeys::model::PrivateKey;
using virgil::sdk::privatekeys::util::JsonKey;


TEST_CASE("Push private key to Container - success", "[virgil-sdk-private-keys]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");

    auto connectionObj = std::make_shared<KeysClientConnection>(VIRGIL_APP_TOKEN,
            PrivateKeysClient::kBaseAddressDefault);
    Mock<KeysClientConnection> connection(*connectionObj);
    When(OverloadedMethod(connection, send, Response(const Request&, const Credentials&))).Return(successResponse);

    auto privateKeysClient = std::make_shared<PrivateKeysClient>(make_moc_shared(connection));
    REQUIRE_NOTHROW(privateKeysClient->privateKey().add(expectedCredentials(), UUID));

    Verify(OverloadedMethod(connection, send, Response(const Request&, const Credentials&)));
}

TEST_CASE("Get a private key - success", "[virgil-sdk-private-keys]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");
    json payload = {
        { JsonKey::publicKeyId, USER_PUBLIC_KEY_ID },
        { JsonKey::privateKey, VirgilBase64::encode(expectedUserPrivateKeyData()) }
    };
    successResponse.body(payload.dump());

    auto connectionObj = std::make_shared<KeysClientConnection>(VIRGIL_APP_TOKEN,
            PrivateKeysClient::kBaseAddressDefault);
    Mock<KeysClientConnection> connection(*connectionObj);
    When(OverloadedMethod(connection, send, Response(const Request&))).Return(successResponse);

    auto privateKeysClient = std::make_shared<PrivateKeysClient>(make_moc_shared(connection));
    PrivateKey privateKey = privateKeysClient->privateKey().get(USER_PUBLIC_KEY_ID);

    Verify(OverloadedMethod(connection, send, Response(const Request&)));

    REQUIRE(privateKey.publicKeyId() == USER_PUBLIC_KEY_ID);
    REQUIRE(privateKey.key() == expectedUserPrivateKeyData());
}

TEST_CASE("Delete private Key - success", "[virgil-sdk-private-keys]") {
    Response successResponse = Response().statusCode(Response::StatusCode::OK).contentType("application/json");

    auto connectionObj = std::make_shared<KeysClientConnection>(VIRGIL_APP_TOKEN,
            PrivateKeysClient::kBaseAddressDefault);
    Mock<KeysClientConnection> connection(*connectionObj);
    When(OverloadedMethod(connection, send, Response(const Request&, const Credentials&))).Return(successResponse);

    auto privateKeysClient = std::make_shared<PrivateKeysClient>(make_moc_shared(connection));
    REQUIRE_NOTHROW(privateKeysClient->privateKey().del(expectedCredentials(), UUID));

    Verify(OverloadedMethod(connection, send, Response(const Request&, const Credentials&)));
}
