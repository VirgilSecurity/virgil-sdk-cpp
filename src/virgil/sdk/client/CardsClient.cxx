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
#include <virgil/sdk/client/CardsClient.h>
#include <virgil/sdk/client/VerifyResponse.h>
#include <virgil/sdk/endpoints/PublicKeysEndpointUri.h>
#include <virgil/sdk/http/Headers.h>
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
using virgil::sdk::client::CardsClient;
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

CardsClient::CardsClient(const std::string& accessToken, const std::string& baseServiceUri)
        : accessToken_(accessToken), baseServiceUri_(baseServiceUri) {
}

Card CardsClient::getServiceCard() const {
    return publicKeysServiceCard_;
}

void CardsClient::setServiceCard(const Card& publicKeysServiceCard) {
    publicKeysServiceCard_ = publicKeysServiceCard;
}

Card CardsClient::create(const ValidatedIdentity& validatedIdentity, const VirgilByteArray& publicKey,
                         const Credentials& credentials) {
    json payload = {{JsonKey::publicKey, VirgilBase64::encode(publicKey)},
                    {JsonKey::identity,
                     {{JsonKey::type, toString(validatedIdentity.getType())},
                      {JsonKey::value, validatedIdentity.getValue()},
                      {JsonKey::validationToken, validatedIdentity.getToken()}}}};

    Request request = Request()
                          .post()
                          .baseAddress(baseServiceUri_)
                          .endpoint(PublicKeysEndpointUri::cardCreate())
                          .body(payload.dump());

    ClientConnection connection(accessToken_);
    Request signRequest = connection.signRequest(credentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_CREATE);
    this->verifyResponse(response);

    Card card = Marshaller<Card>::fromJson(response.body());
    return card;
}

CardSign CardsClient::trust(const std::string& trustedCardId, const std::string& trustedCardHash,
                            const std::string& ownerCardId, const Credentials& credentials) {

    ClientConnection connection(accessToken_);
    json payload = {{JsonKey::signedCardId, trustedCardId},
                    {JsonKey::signedDigest, connection.signHash(trustedCardHash, credentials)}};

    Request request = Request()
                          .post()
                          .baseAddress(baseServiceUri_)
                          .endpoint(PublicKeysEndpointUri::cardTrust(ownerCardId))
                          .body(payload.dump());

    Request signRequest = connection.signRequest(ownerCardId, credentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_TRUST);
    this->verifyResponse(response);

    CardSign cardSign = Marshaller<CardSign>::fromJson(response.body());
    return cardSign;
}

void CardsClient::untrust(const std::string& trustedCardId, const std::string& ownerCardId,
                          const Credentials& credentials) {
    json payload = {{JsonKey::signedCardId, trustedCardId}};

    Request request = Request()
                          .post()
                          .baseAddress(baseServiceUri_)
                          .endpoint(PublicKeysEndpointUri::cardUntrust(ownerCardId))
                          .body(payload.dump());

    ClientConnection connection(accessToken_);
    Request signRequest = connection.signRequest(ownerCardId, credentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_UTRUST);
    this->verifyResponse(response);
}

std::vector<Card> CardsClient::search(const Identity& identity, const std::vector<std::string>& relations,
                                      const bool includeUnconfirmed) {
    json jsonRelations(relations);
    json payload = {{JsonKey::value, identity.getValue()},
                    {JsonKey::type, virgil::sdk::model::toString(identity.getType())},
                    {JsonKey::relations, jsonRelations},
                    {JsonKey::includeUnconfirmed, includeUnconfirmed}};

    Request request = Request()
                          .post()
                          .baseAddress(baseServiceUri_)
                          .endpoint(PublicKeysEndpointUri::cardSearch())
                          .body(payload.dump());

    ClientConnection connection(accessToken_);
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_SEARCH);
    this->verifyResponse(response);

    std::vector<Card> cards = virgil::sdk::io::fromJsonCards(response.body());
    return cards;
}

std::vector<Card> CardsClient::searchApp(const std::string& applicationIdentity) {
    Request request = this->getAppCard(applicationIdentity);
    ClientConnection connection(accessToken_);
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_SEARCH_APP);
    this->verifyResponse(response);

    std::vector<Card> cards = virgil::sdk::io::fromJsonCards(response.body());

    return cards;
}

std::vector<Card> CardsClient::getServiceCard(const std::string& serviceIdentity) {
    Request request = this->getAppCard(serviceIdentity);
    ClientConnection connection(accessToken_);
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_SERVICE_GET);

    std::vector<Card> cards = virgil::sdk::io::fromJsonCards(response.body());
    return cards;
}

std::vector<Card> CardsClient::get(const std::string& publicKeyId, const std::string& cardId,
                                   const Credentials& credentials) {
    Request request =
        Request().get().baseAddress(baseServiceUri_).endpoint(PublicKeysEndpointUri::publicKeyGet(publicKeyId));

    ClientConnection connection(accessToken_);
    Request signRequest = connection.signRequest(cardId, credentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::PUBLIC_KEY_GET_SIGN);
    this->verifyResponse(response);

    json jsonResponseCards = json::parse(response.body());
    std::vector<Card> cards = virgil::sdk::io::fromJsonCards(jsonResponseCards.dump());
    return cards;
}

Card CardsClient::get(const std::string& cardId) {
    Request request = Request().get().baseAddress(baseServiceUri_).endpoint(PublicKeysEndpointUri::cardGet(cardId));

    ClientConnection connection(accessToken_);
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_GET);
    this->verifyResponse(response);

    Card card = Marshaller<Card>::fromJson(response.body());
    return card;
}

void CardsClient::revoke(const std::string& ownerCardId, const ValidatedIdentity& validatedIdentity,
                         const Credentials& credentials) {
    json payload = {{JsonKey::identity,
                     {{JsonKey::type, toString(validatedIdentity.getType())},
                      {JsonKey::value, validatedIdentity.getValue()},
                      {JsonKey::validationToken, validatedIdentity.getToken()}}}};

    Request request = Request()
                          .del()
                          .baseAddress(baseServiceUri_)
                          .endpoint(PublicKeysEndpointUri::cardRevoke(ownerCardId))
                          .body(payload.dump());

    ClientConnection connection(accessToken_);
    Request signRequest = connection.signRequest(ownerCardId, credentials, request);

    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CARD_REVOKE);
    this->verifyResponse(response);
}

Request CardsClient::getAppCard(const std::string& applicationIdentity) {
    json payload = {{JsonKey::value, applicationIdentity}};

    Request request = Request()
                          .post()
                          .baseAddress(baseServiceUri_)
                          .endpoint(PublicKeysEndpointUri::cardSearchApp())
                          .body(payload.dump());

    return request;
}

void CardsClient::verifyResponse(const virgil::sdk::http::Response& response) {
    bool verifed = virgil::sdk::client::verifyResponse(response, publicKeysServiceCard_.getPublicKey().getKey());

    if (!verifed) {
        throw std::runtime_error("CardsClient: The response verification has failed. Signature doesn't match "
                                 "PublicKeyService public key.");
    }
}
