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

#include <virgil/pki/client/UserDataClientBase.h>
using virgil::pki::client::UserDataClientBase;

#include <virgil/pki/client/EndpointUri.h>
using virgil::pki::client::EndpointUri;

#include <virgil/pki/http/Connection.h>
using virgil::pki::http::Connection;
#include <virgil/pki/http/Request.h>
using virgil::pki::http::Request;
#include <virgil/pki/http/Response.h>
using virgil::pki::http::Response;

#include <virgil/pki/model/PublicKey.h>
using virgil::pki::model::PublicKey;

#include <virgil/string/Base64.h>
using virgil::string::Base64;
#include <virgil/string/JsonKey.h>
using virgil::string::JsonKey;

#include <virgil/pki/error/PkiError.h>
using virgil::pki::error::PkiError;

#include <json.hpp>
using json = nlohmann::json;

UserData UserDataClientBase::add(const std::string& publicKeyId, const std::string& className,
        const std::string& type, const std::string& value) const {

    json payload = {
        {JsonKey::publicKeyId, publicKeyId},
        {JsonKey::className, className},
        {JsonKey::type, type},
        {JsonKey::value, value}
    };

    Request request = Request().endpoint(EndpointUri::userDataAdd()).post().contentType("application/json").body(payload.dump());
    Response response = connection()->send(request);
    connection()->checkResponseError(response, PkiError::Action::USER_DATA_ADD);

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

UserData UserDataClientBase::get(const std::string& userDataId) const {
    Request request = Request().endpoint(EndpointUri::userDataGet(userDataId)).get();
    Response response = connection()->send(request);
    connection()->checkResponseError(response, PkiError::Action::USER_DATA_GET);

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

void UserDataClientBase::confirm(const std::string& userDataId, const std::string& code) const {
    json payload = {
        {JsonKey::code, code}
    };

    Request request = Request().endpoint(EndpointUri::userDataConfirm(userDataId)).post()
            .contentType("application/json").body(payload.dump());
    Response response = connection()->send(request);
    connection()->checkResponseError(response, PkiError::Action::USER_DATA_CONFIRM);
}

void UserDataClientBase::resendConfirmation(const std::string& userDataId) const {
    json payload = {};

    Request request = Request().endpoint(EndpointUri::userDataResendConfirm(userDataId)).post()
            .contentType("application/json").body(payload.dump());
    Response response = connection()->send(request);
    connection()->checkResponseError(response, PkiError::Action::USER_DATA_CONFIRM_RESEND);
}

std::vector<UserData> UserDataClientBase::search(const std::string& userId, bool expandPublicKey) const {
    json payload = {
        {JsonKey::id, userId}
    };

    Request request = Request().endpoint(EndpointUri::userDataSearch()).post()
            .contentType("application/json").body(payload.dump());
    if (expandPublicKey) {
        // TODO: Move to the class EndpointUri.
        request.parameters({{"expand", "public_key"}});
    }
    Response response = connection()->send(request);
    connection()->checkResponseError(response, PkiError::Action::USER_DATA_SEARCH);

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
