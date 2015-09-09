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

#include <stdexcept>
#include <json.hpp>

#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/privatekeys/client/Credentials.h>
#include <virgil/sdk/privatekeys/client/EndpointUri.h>
#include <virgil/sdk/privatekeys/client/PrivateKeyEndpoint.h>
#include <virgil/sdk/privatekeys/error/KeysError.h>
#include <virgil/sdk/privatekeys/http/Request.h>
#include <virgil/sdk/privatekeys/http/Response.h>
#include <virgil/sdk/privatekeys/util/JsonKey.h>

using json = nlohmann::json;

using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::privatekeys::client::Credentials;
using virgil::sdk::privatekeys::client::EndpointUri;
using virgil::sdk::privatekeys::client::KeysClientConnection;
using virgil::sdk::privatekeys::error::KeysError;
using virgil::sdk::privatekeys::client::PrivateKeyEndpoint;
using virgil::sdk::privatekeys::model::PrivateKey;
using virgil::sdk::privatekeys::http::Request;
using virgil::sdk::privatekeys::http::Response;
using virgil::sdk::privatekeys::util::JsonKey;


PrivateKeyEndpoint::PrivateKeyEndpoint(const std::shared_ptr<KeysClientConnection>& connection)
        : connection_(connection) {
    if (!connection_) {
        throw std::logic_error("PrivateKeyEndpoint: connection is not defined.");
    }
}

void PrivateKeyEndpoint::add(const Credentials &credentials, const std::string& uuid) const {
    std::string encodePrivateKey = VirgilBase64::encode(credentials.privateKey());
    json payload = {
        { JsonKey::privateKey, encodePrivateKey },
        { JsonKey::requestSignUuid, uuid}
    };

    Request request = Request().endpoint(EndpointUri::v2().addPrivateKey()).post().body(payload.dump());
    Response response = connection_->send(request, credentials);
    connection_->checkResponseError(response, KeysError::Action::ADD_PRIVATE_KEY);
}

PrivateKey PrivateKeyEndpoint::get(const std::string& publicKeyId) const {
    Request request = Request().endpoint(EndpointUri::v2().getPrivateKey(publicKeyId)).get();
    Response response = connection_->send(request);
    connection_->checkResponseError(response, KeysError::Action::GET_PRIVATE_KEY);

    json responseTypeJson = json::parse(response.body());
    std::string responsePublicKeyId = responseTypeJson[JsonKey::publicKeyId];
    std::string responsePrivateKey = responseTypeJson[JsonKey::privateKey];

    PrivateKey privateKey;
    privateKey.publicKeyId(responsePublicKeyId).key(VirgilBase64::decode(responsePrivateKey));
    return privateKey;
}

void PrivateKeyEndpoint::del(const Credentials &credentials, const std::string& uuid) const {
    json payload = {{ JsonKey::requestSignUuid, uuid}};

    Request request = Request().endpoint(EndpointUri::v2().deletePrivateKey()).del().body(payload.dump());
    Response response = connection_->send(request, credentials);
    connection_->checkResponseError(response, KeysError::Action::DELETE_PRIVATE_KEY);
}
