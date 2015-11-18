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

#include <json.hpp>

#include <virgil/sdk/privatekeys/client/ContainerEndpoint.h>
#include <virgil/sdk/privatekeys/client/EndpointUri.h>
#include <virgil/sdk/privatekeys/error/KeysError.h>
#include <virgil/sdk/privatekeys/http/Request.h>
#include <virgil/sdk/privatekeys/http/Response.h>
#include <virgil/sdk/privatekeys/util/JsonKey.h>
#include <virgil/sdk/privatekeys/util/uuid.h>

using json = nlohmann::json;

using virgil::sdk::privatekeys::client::ContainerEndpoint;
using virgil::sdk::privatekeys::client::Credentials;
using virgil::sdk::privatekeys::client::CredentialsExt;
using virgil::sdk::privatekeys::client::EndpointUri;
using virgil::sdk::privatekeys::client::KeysClientConnection;
using virgil::sdk::privatekeys::error::KeysError;
using virgil::sdk::privatekeys::http::Request;
using virgil::sdk::privatekeys::http::Response;
using virgil::sdk::privatekeys::model::ContainerType;
using virgil::sdk::privatekeys::model::UserData;
using virgil::sdk::privatekeys::util::JsonKey;
using virgil::sdk::privatekeys::util::uuid;


static const char * kHttpHeaderField_Athentication = "X-VIRGIL-AUTHENTICATION";


ContainerEndpoint::ContainerEndpoint(const std::shared_ptr<KeysClientConnection>& connection)
        : connection_(connection) {
    if (!connection_) {
        throw std::logic_error("ContainerEndpoint: connection is not defined.");
    }
}

void ContainerEndpoint::create(const CredentialsExt& credentials, const ContainerType& containerType,
        const std::string& containerPassword) const {
        json payload = {
            { JsonKey::containerType, virgil::sdk::privatekeys::model::toString(containerType) },
            { JsonKey::containerPassword, containerPassword },
            { JsonKey::requestSignUuid, uuid() },
        };

        Request request = Request().endpoint(EndpointUri::v2().createContainer()).post().body(payload.dump());
        Response response = connection_->send(request, credentials);
        connection_->checkResponseError(response, KeysError::Action::CREATE_CONTAINER);
}

ContainerType ContainerEndpoint::getDetails(const std::string& publicKeyId) const {
    Request request = Request().endpoint(EndpointUri::v2().getContainerDetails(publicKeyId)).get();

    // Add an authentication token to the header
    auto header = request.header();
    header[kHttpHeaderField_Athentication] = connection_->getAuthToken();
    request.header(header);

    Response response = connection_->send(request);
    connection_->checkResponseError(response, KeysError::Action::GET_CONTAINER_DETAILS);

    json containerTypeJson = json::parse(response.body());
    std::string containerTypeStr = containerTypeJson[JsonKey::containerType];
    return containerTypeStr == "easy" ? ContainerType::Easy : ContainerType::Normal;
}

void ContainerEndpoint::update(const CredentialsExt& credentials, const ContainerType& containerType,
        const std::string& containerPassword) const {
    json payload = {
        { JsonKey::containerType, virgil::sdk::privatekeys::model::toString(containerType) },
        { JsonKey::containerPassword, containerPassword },
        { JsonKey::requestSignUuid, uuid() }
    };

    Request request = Request().endpoint(EndpointUri::v2().updateContainerInformation()).put().body(payload.dump());
    
    //Add an authentication token to the header
    auto header = request.header();
    header[kHttpHeaderField_Athentication] = connection_->getAuthToken();
    request.header(header);

    Response response = connection_->send(request, credentials);
    connection_->checkResponseError(response, KeysError::Action::UPDATE_CONTAINER_INFORMATION);
}

void ContainerEndpoint::resetPassword(const UserData& userData, const std::string& newContainerPassword) const {
     json payload = {
         { JsonKey::userData, {
             { JsonKey::className, userData.className() },
             { JsonKey::type, userData.type() },
             { JsonKey::value, userData.value() }
         }},
         { JsonKey::newContainerPassword, newContainerPassword }
     };

     Request request = Request().endpoint(EndpointUri::v2().resetContainerPassword()).put().body(payload.dump());
     Response response = connection_->send(request);
     connection_->checkResponseError(response, KeysError::Action::RESET_CONTAINER_PASSWORD);
}

void ContainerEndpoint::confirm(const std::string& confirmToken) const {
    json payload = {
        {JsonKey::confirmToken, confirmToken },
        {JsonKey::requestSignUuid, uuid() }
    };

    Request request = Request().endpoint(EndpointUri::v2().confirmToken()).put().body(payload.dump());

    Response response = connection_->send(request);
    connection_->checkResponseError(response, KeysError::Action::CONFIRM_OPERATION);
}

void ContainerEndpoint::del(const CredentialsExt& credentials) const {
    json payload = {{ JsonKey::requestSignUuid, uuid() }};

    Request request = Request().endpoint(EndpointUri::v2().deleteContainer()).del().body(payload.dump());

    // Add an authentication token to the header
    auto header = request.header();
    header[kHttpHeaderField_Athentication] = connection_->getAuthToken();
    request.header(header);

    Response response = connection_->send(request, credentials);
    connection_->checkResponseError(response, KeysError::Action::DELETE_CONTAINER);
}
