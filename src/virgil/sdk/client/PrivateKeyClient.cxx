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

#include <nlohman/json.hpp>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilCipher.h>
#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/Error.h>
#include <virgil/sdk/client/ClientConnection.h>
#include <virgil/sdk/client/PrivateKeyClient.h>
#include <virgil/sdk/endpoints/PrivateKeyEndpointUri.h>
#include <virgil/sdk/http/Request.h>
#include <virgil/sdk/http/Response.h>
#include <virgil/sdk/io/Marshaller.h>
#include <virgil/sdk/dto/Identity.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/uuid.h>

using json = nlohmann::json;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCipher;
using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::Credentials;
using virgil::sdk::Error;
using virgil::sdk::client::ClientConnection;
using virgil::sdk::client::PrivateKeyClient;
using virgil::sdk::endpoints::PrivateKeyEndpointUri;
using virgil::sdk::http::Request;
using virgil::sdk::http::Response;
using virgil::sdk::io::Marshaller;
using virgil::sdk::dto::ValidatedIdentity;
using virgil::sdk::dto::Identity;
using virgil::sdk::models::PrivateKeyModel;
using virgil::sdk::models::CardModel;
using virgil::sdk::util::JsonKey;
using virgil::sdk::util::uuid;

void PrivateKeyClient::add(const std::string& cardId, const Credentials& credentials) {
    json payload = {{JsonKey::privateKey, VirgilBase64::encode(credentials.privateKey())}, {JsonKey::cardId, cardId}};

    Request request = Request()
                          .post()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(PrivateKeyEndpointUri::add())
                          .body(payload.dump());

    ClientConnection connection(this->getAccessToken());
    Request signRequest = connection.signRequest(cardId, credentials, request);

    std::string encryptJsonBody = connection.encryptJsonBody(this->getServiceCard(), payload.dump());

    signRequest.body(encryptJsonBody);
    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::PRIVATE_KEY_ADD);
}

PrivateKeyModel PrivateKeyClient::get(const std::string& cardId, const ValidatedIdentity& validatedIdentity) {
    // Password to encrypt server response. Up to 31 characters
    std::string responsePassword = uuid();
    while (responsePassword.size() > 31) {
        responsePassword.pop_back();
    }

    json payload = {{JsonKey::identity,
                     {{JsonKey::type, validatedIdentity.getType()},
                      {JsonKey::value, validatedIdentity.getValue()},
                      {JsonKey::validationToken, validatedIdentity.getToken()}}},
                    {JsonKey::responsePassword, responsePassword},
                    {JsonKey::cardId, cardId}};

    ClientConnection connection(this->getAccessToken());
    std::string encryptedRequestJsonBody = connection.encryptJsonBody(this->getServiceCard(), payload.dump());

    Request request = Request()
                          .post()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(PrivateKeyEndpointUri::get())
                          .body(encryptedRequestJsonBody);

    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::PRIVATE_KEY_GET);

    VirgilCipher cipher;
    VirgilByteArray decryptResponseBody =
        cipher.decryptWithPassword(VirgilBase64::decode(response.body()), virgil::crypto::str2bytes(responsePassword));

    return Marshaller<PrivateKeyModel>::fromJson(virgil::crypto::bytes2str(decryptResponseBody));
}

void PrivateKeyClient::del(const std::string& cardId, const Credentials& credentials) {
    json payload = {{JsonKey::cardId, cardId}};

    Request request = Request()
                          .post()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(PrivateKeyEndpointUri::del())
                          .body(payload.dump());

    ClientConnection connection(this->getAccessToken());
    Request signRequest = connection.signRequest(cardId, credentials, request);
    std::string encryptJsonBody = connection.encryptJsonBody(this->getServiceCard(), signRequest.body());
    signRequest.body(encryptJsonBody);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::PRIVATE_KEY_DEL);
}
