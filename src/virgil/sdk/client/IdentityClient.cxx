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
#include <stdexcept>

#include <json.hpp>

#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/Error.h>
#include <virgil/sdk/client/ClientConnection.h>
#include <virgil/sdk/client/IdentityClient.h>
#include <virgil/sdk/client/VirgilCardsClient.h>
#include <virgil/sdk/client/VerifyResponse.h>
#include <virgil/sdk/endpoints/IdentityEndpointUri.h>
#include <virgil/sdk/http/Request.h>
#include <virgil/sdk/http/Response.h>
#include <virgil/sdk/io/Marshaller.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/uuid.h>

using json = nlohmann::json;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::Error;
using virgil::sdk::client::IdentityClient;
using virgil::sdk::client::VirgilCardsClient;
using virgil::sdk::client::ClientConnection;
using virgil::sdk::endpoints::IdentityEndpointUri;
using virgil::sdk::http::Request;
using virgil::sdk::http::Response;
using virgil::sdk::io::Marshaller;
using virgil::sdk::model::ValidatedIdentity;
using virgil::sdk::model::Identity;
using virgil::sdk::model::VirgilCard;
using virgil::sdk::util::JsonKey;
using virgil::sdk::util::uuid;

IdentityClient::IdentityClient(const std::string& accessToken, const std::string& baseServiceUri)
        : accessToken_(accessToken), baseServiceUri_(baseServiceUri) {
}

VirgilCard IdentityClient::getServiceVirgilCard() const {
    return identityServiceCard_;
}

void IdentityClient::setServiceVirgilCard(const VirgilCard& identityServiceCard) {
    identityServiceCard_ = identityServiceCard;
}

std::string IdentityClient::verify(const Identity& identity) {
    json payload = {{JsonKey::type, virgil::sdk::model::toString(identity.getType())},
                    {JsonKey::value, identity.getValue()}};

    Request request =
        Request().post().baseAddress(baseServiceUri_).endpoint(IdentityEndpointUri::verify()).body(payload.dump());

    ClientConnection connection(accessToken_);
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::IDENTITY_VERIFY);
    this->verifyResponse(response);

    json jsonResponse = json::parse(response.body());
    std::string actionId = jsonResponse[JsonKey::actionId];
    return actionId;
}

ValidatedIdentity IdentityClient::confirm(const std::string& actionId, const std::string& confirmationCode,
                                          const int timeToLive, const int countToLive) {
    json payload = {{JsonKey::confirmationCode, confirmationCode},
                    {JsonKey::actionId, actionId},
                    {JsonKey::token, {{JsonKey::timeToLive, timeToLive}, {JsonKey::countToLive, countToLive}}}};

    Request request =
        Request().post().baseAddress(baseServiceUri_).endpoint(IdentityEndpointUri::confirm()).body(payload.dump());

    ClientConnection connection(accessToken_);
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::IDENTITY_CONFIRM);
    this->verifyResponse(response);

    ValidatedIdentity validatedIdentity = Marshaller<ValidatedIdentity>::fromJson(response.body());
    return validatedIdentity;
}

bool IdentityClient::isValid(const ValidatedIdentity& validatedIdentity) {
    json payload = {{JsonKey::type, virgil::sdk::model::toString(validatedIdentity.getType())},
                    {JsonKey::value, validatedIdentity.getValue()},
                    {JsonKey::validationToken, validatedIdentity.getToken()}};

    Request request =
        Request().post().baseAddress(baseServiceUri_).endpoint(IdentityEndpointUri::validate()).body(payload.dump());

    ClientConnection connection(accessToken_);
    Response response = connection.send(request);

    // if false throwing exeption
    connection.checkResponseError(response, Error::Action::IDENTITY_IS_VALID);
    this->verifyResponse(response);

    return true;
}

void IdentityClient::verifyResponse(const virgil::sdk::http::Response& response) {
    bool verifed = virgil::sdk::client::verifyResponse(response, identityServiceCard_.getPublicKey().getKey());

    if (!verifed) {
        throw std::runtime_error("IdentityClient: The response verification has failed. Signature doesn't match "
                                 "IdentityService public key.");
    }
}
