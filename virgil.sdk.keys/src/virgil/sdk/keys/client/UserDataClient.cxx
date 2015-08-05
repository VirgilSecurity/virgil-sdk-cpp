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
using virgil::sdk::keys::client::UserDataClient;

#include <virgil/sdk/keys/client/EndpointUri.h>
using virgil::sdk::keys::client::EndpointUri;

#include <virgil/sdk/keys/http/ConnectionBase.h>
using virgil::sdk::keys::http::ConnectionBase;
#include <virgil/sdk/keys/http/Request.h>
using virgil::sdk::keys::http::Request;
#include <virgil/sdk/keys/http/Response.h>
using virgil::sdk::keys::http::Response;

#include <virgil/sdk/keys/model/PublicKey.h>
using virgil::sdk::keys::model::PublicKey;

#include <virgil/sdk/keys/util/Base64.h>
using virgil::sdk::keys::util::Base64;
#include <virgil/sdk/keys/util/JsonKey.h>
using virgil::sdk::keys::util::JsonKey;

#include <virgil/sdk/keys/error/KeysError.h>
using virgil::sdk::keys::error::KeysError;

#include <json.hpp>
using json = nlohmann::json;

UserData UserDataClient::add(const std::string& publicKeyId, const std::string& className,
        const std::string& type, const std::string& value, const std::string& guid) const {

    json payload = {
        {JsonKey::publicKeyId, publicKeyId},
        {JsonKey::className, className},
        {JsonKey::type, type},
        {JsonKey::value, value},
        {JsonKey::guid, guid}
    };

    Request request = Request().endpoint(EndpointUri::userDataAdd()).post().contentType("application/json").body(payload.dump());
    Response response = connection()->send(request);
    connection()->checkResponseError(response, KeysError::Action::USER_DATA_ADD);

    json responseBody = json::parse(response.body());

    UserData userData;
    userData.accountId(responseBody[JsonKey::id][JsonKey::accountId]);
    userData.publicKeyId(responseBody[JsonKey::id][JsonKey::publicKeyId]);
    userData.userDataId(responseBody[JsonKey::id][JsonKey::userDataId]);
    userData.className(responseBody[JsonKey::className]);
    userData.type(responseBody[JsonKey::type]);
    userData.value(responseBody[JsonKey::value]);
    return userData;
}

UserData UserDataClient::get(const std::string& userDataId) const {
    Request request = Request().endpoint(EndpointUri::userDataGet(userDataId)).get();
    Response response = connection()->send(request);
    connection()->checkResponseError(response, KeysError::Action::USER_DATA_GET);

    json responseBody = json::parse(response.body());

    UserData userData;
    userData.accountId(responseBody[JsonKey::id][JsonKey::accountId]);
    userData.publicKeyId(responseBody[JsonKey::id][JsonKey::publicKeyId]);
    userData.userDataId(responseBody[JsonKey::id][JsonKey::userDataId]);
    userData.className(responseBody[JsonKey::className]);
    userData.type(responseBody[JsonKey::type]);
    userData.value(responseBody[JsonKey::value]);
    return userData;
}

void UserDataClient::confirm(const std::string& userDataId, const std::string& code,
        const std::string& guid) const {
    json payload = {
        {JsonKey::code, code},
        {JsonKey::guid, guid}
    };

    Request request = Request().endpoint(EndpointUri::userDataConfirm(userDataId)).post()
            .contentType("application/json").body(payload.dump());
    Response response = connection()->send(request);
    connection()->checkResponseError(response, KeysError::Action::USER_DATA_CONFIRM);
}

void UserDataClient::resendConfirmation(const std::string& userDataId, const std::string& guid) const {
    json payload = {
        {JsonKey::guid, guid}
    };

    Request request = Request().endpoint(EndpointUri::userDataResendConfirm(userDataId)).post()
            .contentType("application/json").body(payload.dump());
    Response response = connection()->send(request);
    connection()->checkResponseError(response, KeysError::Action::USER_DATA_CONFIRM_RESEND);
}

std::vector<UserData> UserDataClient::search(const std::string& userId, bool expandPublicKey) const {
    return search(userId, "id", expandPublicKey);
}

std::vector<UserData> UserDataClient::search(const std::string& userId, const std::string& userIdType,
        bool expandPublicKey) const {
    json payload = {
        {userIdType, userId}
    };

    Request request = Request().endpoint(EndpointUri::userDataSearch()).post()
            .contentType("application/json").body(payload.dump());
    if (expandPublicKey) {
        // TODO: Move to the class EndpointUri.
        request.parameters({{"expand", "public_key"}});
    }
    Response response = connection()->send(request);
    connection()->checkResponseError(response, KeysError::Action::USER_DATA_SEARCH);

    json responseBody = json::parse(response.body());

    std::vector<UserData> allUserData;
    for (auto userDataJson : responseBody) {
        UserData userData;
        userData.accountId(userDataJson[JsonKey::id][JsonKey::accountId]);
        userData.publicKeyId(userDataJson[JsonKey::id][JsonKey::publicKeyId]);
        userData.userDataId(userDataJson[JsonKey::id][JsonKey::userDataId]);
        userData.className(userDataJson[JsonKey::className]);
        userData.type(userDataJson[JsonKey::type]);
        userData.value(userDataJson[JsonKey::value]);
        if (expandPublicKey) {
            auto publicKey = std::make_shared<PublicKey>();
            auto publicKeyJson = userDataJson[JsonKey::expanded][JsonKey::publicKey];
            publicKey->accountId(publicKeyJson[JsonKey::id][JsonKey::accountId]);
            publicKey->publicKeyId(publicKeyJson[JsonKey::id][JsonKey::publicKeyId]);
            publicKey->key(Base64::decode(publicKeyJson[JsonKey::publicKey]));
            userData.publicKey(publicKey);
        }
        allUserData.push_back(userData);
    }
    return allUserData;
}
