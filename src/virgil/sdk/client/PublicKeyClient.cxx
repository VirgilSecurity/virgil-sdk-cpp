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

#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/Error.h>
#include <virgil/sdk/client/ClientConnection.h>
#include <virgil/sdk/client/PublicKeyClient.h>
#include <virgil/sdk/endpoints/PublicKeysEndpointUri.h>
#include <virgil/sdk/http/Request.h>
#include <virgil/sdk/http/Response.h>
#include <virgil/sdk/io/Marshaller.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/uuid.h>

using json = nlohmann::json;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::Credentials;
using virgil::sdk::Error;
using virgil::sdk::client::PublicKeyClient;
using virgil::sdk::client::ClientConnection;
using virgil::sdk::endpoints::PublicKeysEndpointUri;
using virgil::sdk::http::Request;
using virgil::sdk::http::Response;
using virgil::sdk::model::PublicKey;
using virgil::sdk::model::Card;
using virgil::sdk::model::ValidatedIdentity;
using virgil::sdk::model::toString;
using virgil::sdk::io::Marshaller;
using virgil::sdk::util::JsonKey;
using virgil::sdk::util::uuid;

PublicKey PublicKeyClient::get(const std::string& publicKeyId) {
    Request request = Request()
                          .get()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(PublicKeysEndpointUri::publicKeyGet(publicKeyId));

    ClientConnection connection(this->getAccessToken());
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::PUBLIC_KEY_GET_UNSIGN);
    this->verifyResponse(response);
    return Marshaller<PublicKey>::fromJson(response.body());
}

void PublicKeyClient::revoke(const std::string& publicKeyId, const std::vector<ValidatedIdentity> validatedIdentitys,
                              const std::string& cardId, const virgil::sdk::Credentials& credentials) {
    json jsonArray = json::array();
    for (const auto& validatedIdentity : validatedIdentitys) {
        json jsonValidatedIdentity = {{JsonKey::type, toString(validatedIdentity.getType())},
                                      {JsonKey::value, validatedIdentity.getValue()},
                                      {JsonKey::validationToken, validatedIdentity.getToken()}};
        jsonArray.push_back(jsonValidatedIdentity);
    }
    json jsonValidatedIdentitys;
    jsonValidatedIdentitys[JsonKey::identities] = jsonArray;

    Request request = Request()
                          .del()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(PublicKeysEndpointUri::publicKeyRevoke(publicKeyId))
                          .body(jsonValidatedIdentitys.dump());

    ClientConnection connection(this->getAccessToken());
    Request signRequest = connection.signRequest(cardId, credentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::PUBLIC_KEY_REVOKE);
    this->verifyResponse(response);
}
