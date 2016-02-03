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

#include <virgil/sdk/Error.h>
#include <virgil/sdk/client/ClientConnection.h>
#include <virgil/sdk/client/IdentityClient.h>
#include <virgil/sdk/client/VirgilCardsClient.h>
#include <virgil/sdk/client/ResponseVerify.h>
#include <virgil/sdk/endpoints/IdentityEndpointUri.h>
#include <virgil/sdk/http/Request.h>
#include <virgil/sdk/http/Response.h>
#include <virgil/sdk/io/Marshaller.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/uuid.h>

using json = nlohmann::json;

using virgil::crypto::VirgilByteArray;

using virgil::sdk::Error;
using virgil::sdk::client::IdentityClient;
using virgil::sdk::client::VirgilCardsClient;
using virgil::sdk::client::ClientConnection;
using virgil::sdk::endpoints::IdentityEndpointUri;
using virgil::sdk::http::Request;
using virgil::sdk::http::Response;
using virgil::sdk::io::Marshaller;
using virgil::sdk::model::IdentityToken;
using virgil::sdk::model::Identity;
using virgil::sdk::model::VirgilCard;
using virgil::sdk::util::JsonKey;
using virgil::sdk::util::uuid;


IdentityClient::IdentityClient(const std::string& accessToken, const std::string& baseServiceUri)
        : accessToken_(accessToken),
          baseServiceUri_(baseServiceUri) {

}

VirgilByteArray IdentityClient::getServicePublicKey() const {
    return publicKeyIdentityService_;
}

void IdentityClient::setServicePublicKey(const VirgilByteArray& publicKeyIdentityService) {
    publicKeyIdentityService_ = publicKeyIdentityService;
}

std::string IdentityClient::verify(const Identity& identity) {
    Request request = this->verifyRequest(identity);
    ClientConnection connection(accessToken_);
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::IDENTITY_VERIFY);
    this->verifyResponse(response);

    json jsonResponse = json::parse(response.body());
    std::string actionId = jsonResponse["action_id"];
    return actionId;
}

IdentityToken IdentityClient::confirm(const std::string& actionId, const std::string& confirmationCode,
        const int timeToLive, const int countToLive) {

    Request request = this->confirmRequest(actionId, confirmationCode, timeToLive, countToLive);
    ClientConnection connection(accessToken_);
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::IDENTITY_CONFIRM);
    this->verifyResponse(response);

    json jsonResponse = json::parse(response.body());
    IdentityToken identityToken = Marshaller<IdentityToken>::fromJson(jsonResponse);
    return identityToken;
}

bool IdentityClient::isValid(const Identity& identity, const std::string& validationToken) {
    Request request = this->isValidRequest(identity, validationToken);
    ClientConnection connection(accessToken_);
    Response response = connection.send(request);

    // if false throwing exeption
    connection.checkResponseError(response, Error::Action::IDENTITY_IS_VALID);
    this->verifyResponse(response);

    return true;
}

Request IdentityClient::verifyRequest(const Identity& identity) {
    json payload = {
        { JsonKey::type, identity.getTypeAsString() },
        { JsonKey::value, identity.getValue() }
    };

    Request request = Request()
            .post()
            .baseAddress(baseServiceUri_)
            .endpoint(IdentityEndpointUri::verify())
            .body(payload);

    return request;
}

Request IdentityClient::confirmRequest(const std::string& actionId,
        const std::string& confirmationCode, const int timeToLive, const int countToLive) {
    json payload = {
        { JsonKey::confirmationCode, confirmationCode },
        { JsonKey::actionId, actionId },
        { JsonKey::token, {
            { JsonKey::timeToLive, timeToLive },
            { JsonKey::countToLive, countToLive }
        }}
    };

    Request request = Request()
            .post()
            .baseAddress(baseServiceUri_)
            .endpoint(IdentityEndpointUri::confirm())
            .body(payload);

    return request;
}

Request IdentityClient::isValidRequest(const Identity& identity, const std::string& validationToken) {
    json payload = {
        { JsonKey::type, identity.getTypeAsString() },
        { JsonKey::value, identity.getValue() },
        { JsonKey::validationToken, validationToken }
    };

    Request request = Request()
            .post()
            .baseAddress(baseServiceUri_)
            .endpoint(IdentityEndpointUri::validate())
            .body(payload);

    return request;
}

void IdentityClient::verifyResponse(const virgil::sdk::http::Response& response) {
    bool verifed = virgil::sdk::client::verifyResponse(response, publicKeyIdentityService_);
    if ( ! verifed) {
        throw std::runtime_error("IdentityClient: The response verification has failed. Signature doesn't match "
                                 "IdentityService public key.");
    }
}
