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

#include <virgil/sdk/keys/client/UserDataClient.h>

#include <virgil/sdk/keys/client/EndpointUri.h>
#include <virgil/sdk/keys/client/KeysClientConnection.h>
#include <virgil/sdk/keys/http/Request.h>
#include <virgil/sdk/keys/http/Response.h>
#include <virgil/sdk/keys/model/PublicKey.h>
#include <virgil/sdk/keys/util/JsonKey.h>
#include <virgil/sdk/keys/error/KeysError.h>
#include <virgil/sdk/keys/io/Marshaller.h>

#include <json.hpp>

using virgil::sdk::keys::client::UserDataClient;
using virgil::sdk::keys::client::KeysClientConnection;
using virgil::sdk::keys::client::EndpointUri;
using virgil::sdk::keys::client::Credentials;
using virgil::sdk::keys::http::Request;
using virgil::sdk::keys::http::Response;
using virgil::sdk::keys::model::PublicKey;
using virgil::sdk::keys::model::UserData;
using virgil::sdk::keys::util::JsonKey;
using virgil::sdk::keys::error::KeysError;
using virgil::sdk::keys::io::Marshaller;

using json = nlohmann::json;

UserDataClient::UserDataClient(const std::shared_ptr<KeysClientConnection>& connection)
        : connection_(connection) {
    if (!connection_) {
        throw std::logic_error("UserDataClient: ConnectionBase is not defined.");
    }
}

UserData UserDataClient::add(const UserData& userData, const Credentials& credentials,
        const std::string& uuid) const {

    auto payload = Marshaller<UserData>::toJson(userData);
    Request request = Request().endpoint(EndpointUri::v2().userDataAdd()).post().body(payload);
    Response response = connection_->send(request, credentials);
    connection_->checkResponseError(response, KeysError::Action::USER_DATA_ADD);
    return Marshaller<UserData>::fromJson(response.body());
}

void UserDataClient::remove(const std::string& userDataId, const Credentials& credentials,
        const std::string& uuid) const {
    json payload = {
        {JsonKey::uuid, uuid}
    };
    std::string requestUri = EndpointUri::v2().userDataRemove(userDataId);
    Request request = Request().endpoint(requestUri).del().body(payload.dump());
    Response response = connection_->send(request, credentials);
    connection_->checkResponseError(response, KeysError::Action::USER_DATA_DELETE);
}

void UserDataClient::confirm(const std::string& userDataId, const std::string& code) const {
    json payload = {
        {JsonKey::confirmationCode, code},
    };
    std::string requestUri = EndpointUri::v2().userDataConfirm(userDataId);
    Request request = Request().endpoint(requestUri).post().body(payload.dump());
    Response response = connection_->send(request);
    connection_->checkResponseError(response, KeysError::Action::USER_DATA_CONFIRM);
}

void UserDataClient::resendConfirmation(const std::string& userDataId, const Credentials& credentials,
        const std::string& uuid) const {
    json payload = {
        {JsonKey::uuid, uuid}
    };
    std::string requestUri = EndpointUri::v2().userDataConfirm(userDataId);
    Request request = Request().endpoint(requestUri).post().body(payload.dump());
    Response response = connection_->send(request, credentials);
    connection_->checkResponseError(response, KeysError::Action::USER_DATA_CONFIRM_RESEND);
}
