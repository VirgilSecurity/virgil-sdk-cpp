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

#include <iostream>

#include <json.hpp>

#include <virgil/sdk/privatekeys/client/AuthEndpoint.h>
#include <virgil/sdk/privatekeys/client/EndpointUri.h>
#include <virgil/sdk/privatekeys/error/KeysError.h>
#include <virgil/sdk/privatekeys/http/Request.h>
#include <virgil/sdk/privatekeys/http/Response.h>
#include <virgil/sdk/privatekeys/util/JsonKey.h>

using json = nlohmann::json;

using virgil::sdk::privatekeys::client::EndpointUri;
using virgil::sdk::privatekeys::client::AuthEndpoint;
using virgil::sdk::privatekeys::client::KeysClientConnection;
using virgil::sdk::privatekeys::error::KeysError;
using virgil::sdk::privatekeys::http::Request;
using virgil::sdk::privatekeys::http::Response;
using virgil::sdk::privatekeys::model::UserData;
using virgil::sdk::privatekeys::util::JsonKey;


AuthEndpoint::AuthEndpoint(const std::shared_ptr<KeysClientConnection>& connection)
        : connection_(connection) {
    if (!connection_) {
        throw std::logic_error("AuthEndpoint: connection is not defined.");
    }
}

void AuthEndpoint::authenticate(const UserData& userData, const std::string& containerPassword) {
    json payload = json::object();
    payload[JsonKey::containerPassword] = containerPassword;
    payload[JsonKey::userData] = {
        {JsonKey::className, userData.className()},
        {JsonKey::type, userData.type()},
        {JsonKey::value, userData.value()}
    };

    Request request = Request().endpoint(EndpointUri::v2().getAuthToken()).post().body(payload.dump());
    Response response = connection_->send(request);
    connection_->checkResponseError(response, KeysError::Action::GET_AUTH_TOKEN);

    json authTokenJson = json::parse(response.body());
    std::string authToken = authTokenJson[JsonKey::authToken];
    connection_->updateSession(authToken);
}

void AuthEndpoint::authenticate(const std::string& token) {
    connection_->updateSession(token);
}

std::string AuthEndpoint::getAuthToken() const {
    return connection_->getAuthToken();
}