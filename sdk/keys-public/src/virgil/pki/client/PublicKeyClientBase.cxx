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

#include <virgil/pki/client/PublicKeyClientBase.h>
using virgil::pki::client::PublicKeyClientBase;

#include <virgil/pki/client/EndpointUri.h>
using virgil::pki::client::EndpointUri;

#include <virgil/pki/http/Connection.h>
using virgil::pki::http::Connection;
#include <virgil/pki/http/Request.h>
using virgil::pki::http::Request;
#include <virgil/pki/http/Response.h>
using virgil::pki::http::Response;

#include <virgil/string/Base64.h>
using virgil::string::Base64;
#include <virgil/string/JsonKey.h>
using virgil::string::JsonKey;

#include <virgil/pki/error/PkiError.h>
using virgil::pki::error::PkiError;

#include <json.hpp>
using json = nlohmann::json;

PublicKey PublicKeyClientBase::add(const std::vector<unsigned char>& publicKey,
        const std::vector<UserData>& userData, const std::string& accountId) const {

    json payload = json::object();
    if (!accountId.empty()) {
        payload[JsonKey::accountId] = accountId;
    }
    payload[JsonKey::publicKey] = Base64::encode(publicKey);
    payload[JsonKey::userData] = json::array();
    for (auto data : userData) {
        payload[JsonKey::userData].push_back(
            json({
                {JsonKey::className, data.className()},
                {JsonKey::type, data.type()},
                {JsonKey::value, data.value()}
            })
        );
    }

    Request request = Request().endpoint(EndpointUri::publicKeyAdd()).post().body(payload.dump());
    Response response = connection()->send(request);
    connection()->checkResponseError(response, PkiError::Action::PUBLIC_KEY_ADD);

    json responseBody = json::parse(response.body());

    PublicKey pkiPublicKey;
    pkiPublicKey.publicKeyId(responseBody[JsonKey::id][JsonKey::publicKeyId]);
    pkiPublicKey.accountId(responseBody[JsonKey::id][JsonKey::accountId]);
    pkiPublicKey.key(Base64::decode(responseBody[JsonKey::publicKey]));

    return pkiPublicKey;
}

PublicKey PublicKeyClientBase::get(const std::string& publicKeyId) const {
    Request request = Request().endpoint(EndpointUri::publicKeyGet(publicKeyId)).get();
    Response response = connection()->send(request);
    connection()->checkResponseError(response, PkiError::Action::PUBLIC_KEY_GET);

    json responseBody = json::parse(response.body());

    PublicKey pkiPublicKey;
    pkiPublicKey.publicKeyId(responseBody[JsonKey::id][JsonKey::publicKeyId]);
    pkiPublicKey.accountId(responseBody[JsonKey::id][JsonKey::accountId]);
    pkiPublicKey.key(Base64::decode(responseBody[JsonKey::publicKey]));
    for (auto userDataJson : responseBody[JsonKey::userData]) {
        UserData userData;
        userData.className(userDataJson[JsonKey::className]);
        userData.type(userDataJson[JsonKey::type]);
        userData.value(userDataJson[JsonKey::value]);
        userData.isConfirmed(userDataJson[JsonKey::isConfirmed]);
        pkiPublicKey.userData().push_back(userData);
    }
    return pkiPublicKey;
}

std::vector<Account> PublicKeyClientBase::search(const std::string& userId) const {
    json payload = {
        {JsonKey::id, userId}
    };

    Request request = Request().endpoint(EndpointUri::publicKeySearch()).post().body(payload.dump());
    Response response = connection()->send(request);
    connection()->checkResponseError(response, PkiError::Action::PUBLIC_KEY_SEARCH);

    json responseBody = json::parse(response.body());

    std::vector<Account> accounts;
    for (auto accountJson : responseBody) {
        Account account;
        account.accountId(accountJson[JsonKey::id][JsonKey::accountId]);
        for (auto publicKeyJson : accountJson[JsonKey::publicKeys]) {
            PublicKey publicKey;
            publicKey.accountId(publicKeyJson[JsonKey::id][JsonKey::accountId]);
            publicKey.publicKeyId(publicKeyJson[JsonKey::id][JsonKey::publicKeyId]);
            publicKey.key(Base64::decode(publicKeyJson[JsonKey::publicKey]));
            account.publicKeys().push_back(publicKey);
        }
        accounts.push_back(account);
    }
    return accounts;
}
