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

#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/Error.h>
#include <virgil/sdk/client/ClientConnection.h>
#include <virgil/sdk/client/CardClient.h>
#include <virgil/sdk/endpoints/CardEndpointUri.h>
#include <virgil/sdk/endpoints/PublicKeyEndpointUri.h>
#include <virgil/sdk/http/Request.h>
#include <virgil/sdk/http/Response.h>
#include <virgil/sdk/io/Marshaller.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/uuid.h>

using json = nlohmann::json;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::Credentials;
using virgil::sdk::Error;
using virgil::sdk::client::ClientConnection;
using virgil::sdk::client::Client;
using virgil::sdk::client::CardClient;
using virgil::sdk::endpoints::CardEndpointUri;
using virgil::sdk::endpoints::PublicKeyEndpointUri;
using virgil::sdk::http::Request;
using virgil::sdk::http::Response;
using virgil::sdk::io::Marshaller;
using virgil::sdk::models::CardModel;
using virgil::sdk::dto::ValidatedIdentity;
using virgil::sdk::dto::Identity;
using virgil::sdk::models::SignModel;
using virgil::sdk::models::toString;
using virgil::sdk::util::JsonKey;
using virgil::sdk::util::uuid;

const std::string kKeyServiceAppId = "com.virgilsecurity.keys";

CardClient::CardClient(const std::string& accessToken, const std::string& baseServiceUri)
        : Client(accessToken, baseServiceUri, [this]() -> CardModel {
              auto cards = this->searchApp(kKeyServiceAppId, true);
              if (!cards.empty()) {
                  return cards.front();
              } else {
                  throw std::runtime_error("CardClient: Service Card not found on Virgil Keys Service.");
              }
          }) {
}

CardModel CardClient::create(const ValidatedIdentity& validatedIdentity, const VirgilByteArray& publicKey,
                             const Credentials& credentials, const std::map<std::string, std::string>& customData,
                             const std::map<std::string, std::string>& toBeSignedCards) {
    json payload = {{JsonKey::publicKey, VirgilBase64::encode(publicKey)},
                    {JsonKey::identity,
                     {{JsonKey::type, toString(validatedIdentity.getType())},
                      {JsonKey::value, validatedIdentity.getValue()},
                      {JsonKey::validationToken, validatedIdentity.getToken()}}}};
    json jsonCustomData(customData);
    payload[JsonKey::data] = jsonCustomData;
    return this->create(credentials, payload.dump(), toBeSignedCards);
}

CardModel CardClient::create(const ValidatedIdentity& validatedIdentity, const std::string& publicKeyId,
                             const Credentials& credentials, const std::map<std::string, std::string>& customData,
                             const std::map<std::string, std::string>& toBeSignedCards) {
    json payload = {{JsonKey::publicKeyId, publicKeyId},
                    {JsonKey::identity,
                     {{JsonKey::type, toString(validatedIdentity.getType())},
                      {JsonKey::value, validatedIdentity.getValue()},
                      {JsonKey::validationToken, validatedIdentity.getToken()}}}};
    json jsonCustomData(customData);
    payload[JsonKey::data] = jsonCustomData;
    return this->create(credentials, payload.dump(), toBeSignedCards);
}

CardModel CardClient::create(const Identity& identity, const VirgilByteArray& publicKey, const Credentials& credentials,
                             const std::map<std::string, std::string>& customData,
                             const std::map<std::string, std::string>& toBeSignedCards) {
    json payload = {
        {JsonKey::publicKey, VirgilBase64::encode(publicKey)},
        {JsonKey::identity, {{JsonKey::type, toString(identity.getType())}, {JsonKey::value, identity.getValue()}}}};
    json jsonCustomData(customData);
    payload[JsonKey::data] = jsonCustomData;
    return this->create(credentials, payload.dump(), toBeSignedCards);
}

CardModel CardClient::create(const Identity& identity, const std::string& publicKeyId, const Credentials& credentials,
                             const std::map<std::string, std::string>& customData,
                             const std::map<std::string, std::string>& toBeSignedCards) {
    json payload = {
        {JsonKey::publicKeyId, publicKeyId},
        {JsonKey::identity, {{JsonKey::type, toString(identity.getType())}, {JsonKey::value, identity.getValue()}}}};
    json jsonCustomData(customData);
    payload[JsonKey::data] = jsonCustomData;
    return this->create(credentials, payload.dump(), toBeSignedCards);
}

SignModel CardClient::sign(const std::string& toBeSignedCardId, const std::string& toBeSignedCardHash,
                           const std::string& signerCardId, const Credentials& signerCredentials) {

    ClientConnection connection(this->getAccessToken());
    json payload = {{JsonKey::signedCardId, toBeSignedCardId},
                    {JsonKey::signedDigest, connection.signHash(toBeSignedCardHash, signerCredentials)}};

    Request request = Request()
                          .post()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(CardEndpointUri::sign(signerCardId))
                          .body(payload.dump());

    Request signRequest = connection.signRequest(signerCardId, signerCredentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_SIGN);
    this->verifyResponse(response);

    SignModel cardSign = Marshaller<SignModel>::fromJson(response.body());
    return cardSign;
}

void CardClient::unsign(const std::string& signedCardId, const std::string& signOwnerCardId,
                        const virgil::sdk::Credentials& signOwnerCredentials) {

    json payload = {{JsonKey::signedCardId, signedCardId}};

    Request request = Request()
                          .post()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(CardEndpointUri::unsign(signOwnerCardId))
                          .body(payload.dump());

    ClientConnection connection(this->getAccessToken());
    Request signRequest = connection.signRequest(signOwnerCardId, signOwnerCredentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_UNSIGN);
    this->verifyResponse(response);
}

std::vector<CardModel> CardClient::search(const Identity& identity, const bool includeUnconfirmed,
                                          const std::vector<std::string>& relations) {
    json jsonRelations(relations);
    json payload = {{JsonKey::value, identity.getValue()},
                    {JsonKey::type, virgil::sdk::models::toString(identity.getType())},
                    {JsonKey::relations, jsonRelations},
                    {JsonKey::includeUnconfirmed, includeUnconfirmed}};

    Request request = Request()
                          .post()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(CardEndpointUri::search())
                          .body(payload.dump());

    ClientConnection connection(this->getAccessToken());
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_SEARCH);
    this->verifyResponse(response);

    std::vector<CardModel> cards = virgil::sdk::io::cardsFromJson(response.body());
    return cards;
}

std::vector<CardModel> CardClient::searchApp(const std::string& applicationIdentity, bool skipVerification) const {
    json payload = {{JsonKey::value, applicationIdentity}};
    Request request = Request()
                          .post()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(CardEndpointUri::searchApp())
                          .body(payload.dump());

    ClientConnection connection(this->getAccessToken());
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_SEARCH_APP);
    if (!skipVerification) {
        this->verifyResponse(response);
    }

    std::vector<CardModel> cards = virgil::sdk::io::cardsFromJson(response.body());

    return cards;
}

CardModel CardClient::get(const std::string& cardId) {
    Request request = Request().get().baseAddress(this->getBaseServiceUri()).endpoint(CardEndpointUri::get(cardId));

    ClientConnection connection(this->getAccessToken());
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_GET);
    this->verifyResponse(response);

    CardModel card = Marshaller<CardModel>::fromJson(response.body());
    return card;
}

std::vector<CardModel> CardClient::get(const std::string& publicKeyId, const std::string& cardId,
                                       const Credentials& credentials) {
    Request request =
        Request().get().baseAddress(this->getBaseServiceUri()).endpoint(PublicKeyEndpointUri::get(publicKeyId));

    ClientConnection connection(this->getAccessToken());
    Request signRequest = connection.signRequest(cardId, credentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::PUBLIC_KEY_GET_SIGN);
    this->verifyResponse(response);

    json jsonResponseCards = json::parse(response.body());
    std::vector<CardModel> cards = virgil::sdk::io::cardsFromJson(jsonResponseCards.dump());
    return cards;
}

void CardClient::revoke(const std::string& cardId, const ValidatedIdentity& validatedIdentity,
                        const Credentials& credentials) {
    json payload = {{JsonKey::identity,
                     {{JsonKey::type, toString(validatedIdentity.getType())},
                      {JsonKey::value, validatedIdentity.getValue()},
                      {JsonKey::validationToken, validatedIdentity.getToken()}}}};

    Request request = Request()
                          .del()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(CardEndpointUri::revoke(cardId))
                          .body(payload.dump());

    ClientConnection connection(this->getAccessToken());
    Request signRequest = connection.signRequest(cardId, credentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_REVOKE);
    this->verifyResponse(response);
}

void CardClient::revoke(const std::string& cardId, const Identity& identity, const Credentials& credentials) {
    json payload = {
        {JsonKey::identity, {{JsonKey::type, toString(identity.getType())}, {JsonKey::value, identity.getValue()}}}};

    Request request = Request()
                          .del()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(CardEndpointUri::revoke(cardId))
                          .body(payload.dump());

    ClientConnection connection(this->getAccessToken());
    Request signRequest = connection.signRequest(cardId, credentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_REVOKE);
    this->verifyResponse(response);
}

CardModel CardClient::create(const virgil::sdk::Credentials& credentials, const std::string& payload,
                             const std::map<std::string, std::string>& toBeSignedCards) {
    json jsonPayload = json::parse(payload);
    ClientConnection connection(this->getAccessToken());
    if (!toBeSignedCards.empty()) {
        json signs = json::array();
        for (const auto& toBeSignedCard : toBeSignedCards) {
            std::string signedHash = connection.signHash(toBeSignedCard.second, credentials);
            json sign = {{JsonKey::signedCardId, toBeSignedCard.first}, {JsonKey::signedDigest, signedHash}};
            signs.push_back(sign);
        }
        jsonPayload[JsonKey::signs] = signs;
    }

    Request request = Request()
                          .post()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(CardEndpointUri::create())
                          .body(jsonPayload.dump());

    Request signRequest = connection.signRequest(credentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_CREATE);
    this->verifyResponse(response);

    CardModel card = Marshaller<CardModel>::fromJson(response.body());
    return card;
}
