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

#include <string>

#include <stdexcept>

#include <nlohman/json.hpp>

#include <virgil/crypto/VirgilCipher.h>
#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilSigner.h>
#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/client/ClientConnection.h>
#include <virgil/sdk/http/Headers.h>
#include <virgil/sdk/http/Request.h>
#include <virgil/sdk/http/Response.h>
#include <virgil/sdk/Error.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/uuid.h>
#include <virgil/sdk/Credentials.h>

using json = nlohmann::json;

using virgil::crypto::VirgilCipher;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilSigner;
using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::Credentials;
using virgil::sdk::Error;
using virgil::sdk::client::ClientConnection;
using virgil::sdk::http::Connection;
using virgil::sdk::http::Request;
using virgil::sdk::http::Response;
using virgil::sdk::models::CardModel;
using virgil::sdk::util::JsonKey;

using virgil::sdk::http::kHeaderField_Id;
using virgil::sdk::http::kHeaderField_SignCardId;
using virgil::sdk::http::kHeaderField_Sign;
using virgil::sdk::http::kHeaderField_AccessToken;

ClientConnection::ClientConnection(const std::string& accessToken) : accessToken_(accessToken) {
}

std::string ClientConnection::accessToken() const {
    return accessToken_;
}

Response ClientConnection::send(const Request& request) {
    // Add application token to the header
    auto header = request.header();
    header[kHeaderField_AccessToken] = this->accessToken();
    return Connection::send(Request(request).header(header).contentType("application/json"));
}

Request ClientConnection::signRequest(const std::string& cardId, const Credentials& credentials,
                                      const Request& request) {
    Request requestWithoutCardId = signRequest(credentials, request);
    auto header = requestWithoutCardId.header();
    header[kHeaderField_SignCardId] = cardId;
    return Request(requestWithoutCardId).header(header);
}

Request ClientConnection::signRequest(const Credentials& credentials, const Request& request) {
    std::string uuid = virgil::sdk::util::uuid();
    std::string requestText = uuid + request.body();

    VirgilSigner signer;
    VirgilByteArray sign =
        signer.sign(virgil::crypto::str2bytes(requestText), credentials.privateKey(), credentials.privateKeyPassword());

    auto headers = request.header();
    headers[kHeaderField_Id] = uuid;
    headers[kHeaderField_Sign] = VirgilBase64::encode(sign);
    return Request(request).header(headers);
}

std::string ClientConnection::signHash(const std::string& hash, const Credentials& credentials) {
    VirgilSigner signer;
    VirgilByteArray signHash =
        signer.sign(virgil::crypto::str2bytes(hash), credentials.privateKey(), credentials.privateKeyPassword());

    return VirgilBase64::encode(signHash);
}

std::string ClientConnection::encryptJsonBody(const CardModel& privateKeysServiceCard, const std::string& jsonBody) {
    VirgilCipher cipher;
    cipher.addKeyRecipient(virgil::crypto::str2bytes(privateKeysServiceCard.getId()),
                           privateKeysServiceCard.getPublicKey().getKey());

    VirgilByteArray encryptedJsonBody = cipher.encrypt(virgil::crypto::str2bytes(jsonBody), true);
    return VirgilBase64::encode(encryptedJsonBody);
}

void ClientConnection::checkResponseError(const Response& response, Error::Action action) {
    if (response.fail()) {
        unsigned int errorCode = Error::kUndefinedErrorCode;
        if (!response.body().empty()) {
            json error = json::parse(response.body());
            json code = error[JsonKey::errorCode];
            if (code.is_number()) {
                errorCode = code.get<unsigned int>();
            }
        }
        throw Error(action, response.statusCode(), errorCode);
    }
}
