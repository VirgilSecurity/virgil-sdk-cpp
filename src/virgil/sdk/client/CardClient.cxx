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
#include <json.hpp>

#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/Error.h>
#include <virgil/sdk/client/ClientConnection.h>
#include <virgil/sdk/client/CardClient.h>
#include <virgil/sdk/endpoints/PublicKeysEndpointUri.h>
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
using virgil::sdk::endpoints::PublicKeysEndpointUri;
using virgil::sdk::http::Request;
using virgil::sdk::http::Response;
using virgil::sdk::io::Marshaller;
using virgil::sdk::model::Card;
using virgil::sdk::model::ValidatedIdentity;
using virgil::sdk::model::Identity;
using virgil::sdk::model::CardSign;
using virgil::sdk::model::toString;
using virgil::sdk::util::JsonKey;
using virgil::sdk::util::uuid;

const std::string kKeyServiceAppId = "com.virgilsecurity.keys";

CardClient::CardClient(const std::string& accessToken, const std::string& baseServiceUri)
        : Client(accessToken, baseServiceUri, [this]() -> Card {
              auto cards = this->getServiceCard(kKeyServiceAppId);
              if (!cards.empty()) {
                  return cards.front();
              } else {
                  throw std::runtime_error("CardClient: Service Card not found on Virgil Keys Service.");
              }
          }) {
}

Card CardClient::create(const ValidatedIdentity& validatedIdentity, const VirgilByteArray& publicKey,
                        const Credentials& credentials) {
    json payload = {{JsonKey::publicKey, VirgilBase64::encode(publicKey)},
                    {JsonKey::identity,
                     {{JsonKey::type, toString(validatedIdentity.getType())},
                      {JsonKey::value, validatedIdentity.getValue()},
                      {JsonKey::validationToken, validatedIdentity.getToken()}}}};

    Request request = Request()
                          .post()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(PublicKeysEndpointUri::cardCreate())
                          .body(payload.dump());

    ClientConnection connection(this->getAccessToken());
    Request signRequest = connection.signRequest(credentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_CREATE);
    this->verifyResponse(response);

    Card card = Marshaller<Card>::fromJson(response.body());
    return card;
}

CardSign CardClient::sign(const std::string& toBeSignedCardId, const std::string& toBeSignedCardHash,
                          const std::string& signerCardId, const Credentials& signerCredentials) {

    ClientConnection connection(this->getAccessToken());
    json payload = {{JsonKey::signedCardId, toBeSignedCardId},
                    {JsonKey::signedDigest, connection.signHash(toBeSignedCardHash, signerCredentials)}};

    Request request = Request()
                          .post()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(PublicKeysEndpointUri::cardTrust(signerCardId))
                          .body(payload.dump());

    Request signRequest = connection.signRequest(signerCardId, signerCredentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_TRUST);
    this->verifyResponse(response);

    CardSign cardSign = Marshaller<CardSign>::fromJson(response.body());
    return cardSign;
}

void CardClient::unsign(const std::string& signedCardId, const std::string& signOwnerCardId,
                        const virgil::sdk::Credentials& signOwnerCredentials) {

    json payload = {{JsonKey::signedCardId, signedCardId}};

    Request request = Request()
                          .post()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(PublicKeysEndpointUri::cardUnsign(signOwnerCardId))
                          .body(payload.dump());

    ClientConnection connection(this->getAccessToken());
    Request signRequest = connection.signRequest(signOwnerCardId, signOwnerCredentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_UTRUST);
    this->verifyResponse(response);
}

std::vector<Card> CardClient::search(const Identity& identity, const std::vector<std::string>& relations,
                                     const bool includeUnconfirmed) {
    json jsonRelations(relations);
    json payload = {{JsonKey::value, identity.getValue()},
                    {JsonKey::type, virgil::sdk::model::toString(identity.getType())},
                    {JsonKey::relations, jsonRelations},
                    {JsonKey::includeUnconfirmed, includeUnconfirmed}};

    Request request = Request()
                          .post()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(PublicKeysEndpointUri::cardSearch())
                          .body(payload.dump());

    ClientConnection connection(this->getAccessToken());
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_SEARCH);
    this->verifyResponse(response);

    std::vector<Card> cards = virgil::sdk::io::cardsFromJson(response.body());
    return cards;
}

std::vector<Card> CardClient::searchApp(const std::string& applicationIdentity) {
    Request request = this->getAppCard(applicationIdentity);
    ClientConnection connection(this->getAccessToken());
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_SEARCH_APP);
    this->verifyResponse(response);

    std::vector<Card> cards = virgil::sdk::io::cardsFromJson(response.body());

    return cards;
}

std::vector<Card> CardClient::getServiceCard(const std::string& serviceIdentity) const {
    Request request = this->getAppCard(serviceIdentity);
    ClientConnection connection(this->getAccessToken());
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_SERVICE_GET);
    return virgil::sdk::io::cardsFromJson(response.body());
}

std::vector<Card> CardClient::get(const std::string& publicKeyId, const std::string& cardId,
                                  const Credentials& credentials) {
    Request request = Request()
                          .get()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(PublicKeysEndpointUri::publicKeyGet(publicKeyId));

    ClientConnection connection(this->getAccessToken());
    Request signRequest = connection.signRequest(cardId, credentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::PUBLIC_KEY_GET_SIGN);
    this->verifyResponse(response);

    json jsonResponseCards = json::parse(response.body());
    std::vector<Card> cards = virgil::sdk::io::cardsFromJson(jsonResponseCards.dump());
    return cards;
}

Card CardClient::get(const std::string& cardId) {
    Request request =
        Request().get().baseAddress(this->getBaseServiceUri()).endpoint(PublicKeysEndpointUri::cardGet(cardId));

    ClientConnection connection(this->getAccessToken());
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_GET);
    this->verifyResponse(response);

    Card card = Marshaller<Card>::fromJson(response.body());
    return card;
}

void CardClient::revoke(const std::string& signerCardId, const ValidatedIdentity& validatedIdentity,
                        const Credentials& credentials) {
    json payload = {{JsonKey::identity,
                     {{JsonKey::type, toString(validatedIdentity.getType())},
                      {JsonKey::value, validatedIdentity.getValue()},
                      {JsonKey::validationToken, validatedIdentity.getToken()}}}};

    Request request = Request()
                          .del()
                          .baseAddress(this->getBaseServiceUri())
                          .endpoint(PublicKeysEndpointUri::cardRevoke(signerCardId))
                          .body(payload.dump());

    ClientConnection connection(this->getAccessToken());
    Request signRequest = connection.signRequest(signerCardId, credentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_REVOKE);
    this->verifyResponse(response);
}

Request CardClient::getAppCard(const std::string& applicationIdentity) const {
    json payload = {{JsonKey::value, applicationIdentity}};

    return Request()
        .post()
        .baseAddress(this->getBaseServiceUri())
        .endpoint(PublicKeysEndpointUri::cardSearchApp())
        .body(payload.dump());
}
