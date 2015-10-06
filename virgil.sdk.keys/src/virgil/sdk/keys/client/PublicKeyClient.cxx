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

#include <virgil/sdk/keys/client/PublicKeyClient.h>
#include <virgil/sdk/keys/client/EndpointUri.h>
#include <virgil/sdk/keys/client/KeysClientConnection.h>
#include <virgil/sdk/keys/http/Request.h>
#include <virgil/sdk/keys/http/Response.h>
#include <virgil/sdk/keys/util/JsonKey.h>
#include <virgil/sdk/keys/error/KeysError.h>
#include <virgil/sdk/keys/io/Marshaller.h>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilSigner.h>
#include <virgil/crypto/foundation/VirgilBase64.h>

#include <json.hpp>

using virgil::sdk::keys::client::PublicKeyClient;
using virgil::sdk::keys::client::KeysClientConnection;
using virgil::sdk::keys::client::EndpointUri;
using virgil::sdk::keys::client::Credentials;
using virgil::sdk::keys::model::PublicKey;
using virgil::sdk::keys::model::UserData;
using virgil::sdk::keys::http::Request;
using virgil::sdk::keys::http::Response;
using virgil::sdk::keys::util::JsonKey;
using virgil::sdk::keys::error::KeysError;
using virgil::sdk::keys::io::Marshaller;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilSigner;
using virgil::crypto::foundation::VirgilBase64;

using json = nlohmann::json;

PublicKeyClient::PublicKeyClient(const std::shared_ptr<KeysClientConnection>& connection)
        : connection_(connection) {
    if (!connection_) {
        throw std::logic_error("PublicKeyClient: ConnectionBase is not defined.");
    }
}

PublicKey PublicKeyClient::add(const std::vector<unsigned char>& key,
        const std::vector<UserData>& userData, const Credentials& credentials, const std::string& uuid) const {
    json payload = json::object();
    payload[JsonKey::publicKey] = VirgilBase64::encode(key);
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
    payload[JsonKey::uuid] = uuid;

    Request request = Request().endpoint(EndpointUri::v2().publicKeyAdd()).post().body(payload.dump());
    Response response = connection_->send(request, credentials);
    connection_->checkResponseError(response, KeysError::Action::PUBLIC_KEY_ADD);
    return Marshaller<PublicKey>::fromJson(response.body());
}

virgil::sdk::keys::model::PublicKey PublicKeyClient::get(const std::string& publicKeyId) const {
    Request request = Request().endpoint(EndpointUri::v2().publicKeyGet(publicKeyId)).get();
    Response response = connection_->send(request);
    connection_->checkResponseError(response, KeysError::Action::PUBLIC_KEY_GET);
    return Marshaller<PublicKey>::fromJson(response.body());
}

PublicKey PublicKeyClient::update(const std::vector<unsigned char>& newKey,
        const Credentials& newKeyCredentials, const Credentials& oldKeyCredentials,
        const std::string& uuid) const {
    json payload = json::object();
    payload[JsonKey::publicKey] = VirgilBase64::encode(newKey);
    payload[JsonKey::uuid] = uuid;
    payload[JsonKey::uuidSign] = VirgilBase64::encode(VirgilSigner().sign(virgil::crypto::str2bytes(uuid),
            newKeyCredentials.privateKey(), virgil::crypto::str2bytes(newKeyCredentials.privateKeyPassword())));

    std::string requestUri = EndpointUri::v2().publicKeyUpdate(oldKeyCredentials.publicKeyId());
    Request request = Request().endpoint(requestUri).put().body(payload.dump());
    Response response = connection_->send(request, oldKeyCredentials);
    connection_->checkResponseError(response, KeysError::Action::PUBLIC_KEY_UPDATE);

    return Marshaller<PublicKey>::fromJson(response.body());
}

void PublicKeyClient::del(const Credentials& credentials, const std::string& uuid) const {
    json payload = {
        {JsonKey::uuid, uuid}
    };

    std::string requestUri = EndpointUri::v2().publicKeyDelete(credentials.publicKeyId());
    Request request = Request().endpoint(requestUri).del().body(payload.dump());
    Response response = connection_->send(request, credentials);
    connection_->checkResponseError(response, KeysError::Action::PUBLIC_KEY_DELETE);
}

std::string PublicKeyClient::del(const std::string& publicKeyId, const std::string& uuid) const {
    json payload = {
        {JsonKey::uuid, uuid}
    };

    std::string requestUri = EndpointUri::v2().publicKeyDelete(publicKeyId);
    Request request = Request().endpoint(requestUri).del().body(payload.dump());
    Response response = connection_->send(request);
    connection_->checkResponseError(response, KeysError::Action::PUBLIC_KEY_DELETE);
    return response.body();
}

void PublicKeyClient::confirmDel(const std::string& publicKeyId, const std::string& actionToken,
        const std::vector<std::string>& confirmationCodes) const {
    json payload = {
        {JsonKey::actionToken, actionToken},
        {JsonKey::confirmationCodes, confirmationCodes}
    };

    std::string requestUri = EndpointUri::v2().publicKeyConfirmDelete(publicKeyId);
    Request request = Request().endpoint(requestUri).post().body(payload.dump());
    Response response = connection_->send(request);
    connection_->checkResponseError(response, KeysError::Action::PUBLIC_KEY_CONFIRM_DELETE);
}

std::string PublicKeyClient::reset(const std::string& oldPublicKeyId, const std::vector<unsigned char>& newKey,
        const Credentials& newKeyCredentials, const std::string& uuid) const {
    json payload = {
        {JsonKey::publicKey, VirgilBase64::encode(newKey)},
        {JsonKey::uuid, uuid}
    };

    std::string requestUri = EndpointUri::v2().publicKeyReset(oldPublicKeyId);
    Request request = Request().endpoint(requestUri).post().body(payload.dump());
    Response response = connection_->send(request, newKeyCredentials);
    connection_->checkResponseError(response, KeysError::Action::PUBLIC_KEY_RESET);
    return response.body();
}

PublicKey PublicKeyClient::confirmReset(const std::string& oldPublicKeyId, const Credentials& newKeyCredentials,
        const std::string& actionToken, const std::vector<std::string>& confirmationCodes) const {
    json payload = {
        {JsonKey::actionToken, actionToken},
        {JsonKey::confirmationCodes, confirmationCodes}
    };

    std::string requestUri = EndpointUri::v2().publicKeyConfirmReset(oldPublicKeyId);
    Request request = Request().endpoint(requestUri).post().body(payload.dump());

    Response response = connection_->send(request, newKeyCredentials);
    connection_->checkResponseError(response, KeysError::Action::PUBLIC_KEY_CONFIRM_RESET);
    return Marshaller<PublicKey>::fromJson(response.body());
}

PublicKey PublicKeyClient::grab(const std::string& userId, const std::string& uuid) const {
    json payload = {
        {JsonKey::value, userId},
        {JsonKey::uuid, uuid}
    };

    Request request = Request().endpoint(EndpointUri::v2().publicKeyGrab()).post().body(payload.dump());
    Response response = connection_->send(request);
    connection_->checkResponseError(response, KeysError::Action::PUBLIC_KEY_GRAB);
    return Marshaller<PublicKey>::fromJson(response.body());
}

PublicKey PublicKeyClient::grab(const Credentials& credentials, const std::string& uuid) const {
    json payload = {
        {JsonKey::uuid, uuid}
    };

    Request request = Request().endpoint(EndpointUri::v2().publicKeyGrab()).post().body(payload.dump());
    Response response = connection_->send(request, credentials);
    connection_->checkResponseError(response, KeysError::Action::PUBLIC_KEY_GRAB);
    return Marshaller<PublicKey>::fromJson(response.body());
}
