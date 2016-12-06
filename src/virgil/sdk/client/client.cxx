/**
 * Copyright (C) 2016 Virgil Security Inc.
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

#include <virgil/sdk/client/Client.h>
#include <virgil/sdk/http/ClientRequest.h>
#include <virgil/sdk/http/Response.h>
#include <virgil/sdk/endpoints/CardEndpointUri.h>
#include <virgil/sdk/client/models/serialization/JsonSerializer.h>
#include <virgil/sdk/client/models/serialization/JsonDeserializer.h>
#include <virgil/sdk/client/models/responses/CardResponse.h>
#include <virgil/sdk/client/models/responses/CardsResponse.h>
#include <virgil/sdk/http/Connection.h>
#include <virgil/sdk/VirgilSdkError.h>
#include <virgil/sdk/client/models/errors/VirgilError.h>

static_assert(!std::is_abstract<virgil::sdk::client::Client>(), "Client must not be abstract.");

using virgil::sdk::make_error;
using virgil::sdk::client::Client;
using virgil::sdk::http::Connection;
using virgil::sdk::http::ClientRequest;
using virgil::sdk::http::Response;
using virgil::sdk::endpoints::CardEndpointUri;
using virgil::sdk::client::models::serialization::JsonSerializer;
using virgil::sdk::client::models::serialization::JsonDeserializer;
using virgil::sdk::client::models::responses::CardResponse;
using virgil::sdk::client::models::responses::CardsResponse;
using virgil::sdk::client::models::interfaces::SignableRequestInterface;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::requests::RevokeCardRequest;
using virgil::sdk::client::models::Card;
using virgil::sdk::client::models::SearchCardsCriteria;
using virgil::sdk::client::ServiceConfig;
using virgil::sdk::client::models::errors::Error;
using virgil::sdk::client::models::errors::VirgilError;

Client::Client(std::string accessToken)
        : Client(ServiceConfig::createConfig(std::move(accessToken))) {
}

Client::Client(ServiceConfig serviceConfig)
        : serviceConfig_(std::move(serviceConfig)) {
}

Error Client::parseError(const http::Response &response) const {
    try {
        auto virgilError = JsonDeserializer<VirgilError>::fromJsonString(response.body());
        return Error(response.statusCodeRaw(), virgilError);
    }
    catch (...) {
        return Error(response.statusCodeRaw(), VirgilError(0));
    }
}

std::future<Card> Client::createCard(const CreateCardRequest &request) const {
    auto future = std::async([=]{
        ClientRequest httpRequest = ClientRequest(this->serviceConfig_.token());
        httpRequest
                .post()
                .baseAddress(this->serviceConfig_.cardsServiceURL())
                .endpoint(CardEndpointUri::create())
                .body(JsonSerializer<SignableRequestInterface>::toJson(request));

        Connection connection;
        Response response = connection.send(httpRequest);

        if (response.fail()) {
            auto error = this->parseError(response);
            throw make_error(VirgilSdkError::ServiceQueryFailed, error.errorMsg());
        }

        auto cardResponse = JsonDeserializer<CardResponse>::fromJsonString(response.body());

        if (this->serviceConfig_.cardValidator() != nullptr) {
            if (!this->serviceConfig_.cardValidator()->validateCardResponse(cardResponse)) {
                throw make_error(VirgilSdkError::CardValidationFailed, "Card validation failed.");
            }
        }

        return cardResponse.buildCard();
    });

    return future;
}

std::future<Card> Client::getCard(const std::string &cardId) const {
    auto future = std::async([=]{
        ClientRequest httpRequest = ClientRequest(this->serviceConfig_.token());
        httpRequest
                .get()
                .baseAddress(this->serviceConfig_.cardsServiceROURL())
                .endpoint(CardEndpointUri::get(cardId));

        Connection connection;
        Response response = connection.send(httpRequest);

        if (response.fail()) {
            auto error = this->parseError(response);
            throw make_error(VirgilSdkError::ServiceQueryFailed, error.errorMsg());
        }

        auto cardResponse = JsonDeserializer<CardResponse>::fromJsonString(response.body());

        if (this->serviceConfig_.cardValidator() != nullptr) {
            if (!this->serviceConfig_.cardValidator()->validateCardResponse(cardResponse)) {
                throw make_error(VirgilSdkError::CardValidationFailed, "Card validation failed.");
            }
        }

        return cardResponse.buildCard();
    });

    return future;
}

std::future<std::vector<Card>> Client::searchCards(const SearchCardsCriteria &criteria) const {
    auto future = std::async([=]{
        ClientRequest httpRequest = ClientRequest(this->serviceConfig_.token());
        httpRequest
                .post()
                .baseAddress(this->serviceConfig_.cardsServiceROURL())
                .endpoint(CardEndpointUri::search())
                .body(JsonSerializer<SearchCardsCriteria>::toJson(criteria));

        Connection connection;
        Response response = connection.send(httpRequest);

        if (response.fail()) {
            auto error = this->parseError(response);
            throw make_error(VirgilSdkError::ServiceQueryFailed, error.errorMsg());
        }

        auto cardsResponse = JsonDeserializer<CardsResponse>::fromJsonString(response.body());

        if (this->serviceConfig_.cardValidator() != nullptr) {
            for (const auto &cardResponse : cardsResponse.cardsResponse()) {
                if (!this->serviceConfig_.cardValidator()->validateCardResponse(cardResponse)) {
                    throw make_error(VirgilSdkError::CardValidationFailed, "Card validation failed.");
                }
            }
        }

        return cardsResponse.buildCards();
    });

    return future;
}

std::future<void> Client::revokeCard(const RevokeCardRequest &request) const {
    auto future = std::async([=]{
        ClientRequest httpRequest = ClientRequest(this->serviceConfig_.token());
        httpRequest
                .del()
                .baseAddress(this->serviceConfig_.cardsServiceURL())
                .endpoint(CardEndpointUri::revoke(request.snapshotModel().cardId()))
                .body(JsonSerializer<SignableRequestInterface>::toJson(request));

        Connection connection;
        Response response = connection.send(httpRequest);

        if (response.fail()) {
            auto error = this->parseError(response);
            throw make_error(VirgilSdkError::ServiceQueryFailed, error.errorMsg());
        }

        return;
    });

    return future;
}
