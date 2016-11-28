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
#include <virgil/sdk/client/models/responses/CardResponse.h>
#include <virgil/sdk/http/Connection.h>

static_assert(!std::is_abstract<virgil::sdk::client::Client>(), "Client must not be abstract.");

using virgil::sdk::client::Client;
using virgil::sdk::http::Connection;
using virgil::sdk::http::ClientRequest;
using virgil::sdk::http::Response;
using virgil::sdk::endpoints::CardEndpointUri;
using virgil::sdk::client::models::serialization::JsonSerializer;
using virgil::sdk::client::models::responses::CardResponse;
using virgil::sdk::client::models::interfaces::SignableRequestInterface;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::Card;

Client::Client(std::string accessToken, std::string baseServiceUri)
        : accessToken_(std::move(accessToken)),
          baseServiceUri_(std::move(baseServiceUri)) {
}

const std::string& Client::accessToken() const {
    return accessToken_;
}

const std::string& Client::baseServiceUri() const {
    return baseServiceUri_;
}

std::future<Card> Client::createCard(const CreateCardRequest &request) const {
    auto future = std::async([=]{
        ClientRequest httpRequest = ClientRequest(this->accessToken());
        httpRequest
                .post()
                .baseAddress(this->baseServiceUri())
                .endpoint(CardEndpointUri::create())
                .body(JsonSerializer<SignableRequestInterface>::toJson(request));

        Connection connection;
        Response response = connection.send(httpRequest);

        auto cardResponse = JsonSerializer<CardResponse>::fromJson(response.body());

        return cardResponse.buildCard();
    });

    return future;
}

std::future<Card> Client::getCard(const std::string &cardId) const {
    auto future = std::async([=]{
        ClientRequest httpRequest = ClientRequest(this->accessToken());
        httpRequest
                .get()
                .baseAddress(this->baseServiceUri())
                .endpoint(CardEndpointUri::get(cardId));

        Connection connection;
        Response response = connection.send(httpRequest);

        return JsonSerializer<CardResponse>::fromJson(response.body()).buildCard();
    });

    return future;
}

std::future<std::vector<Card>> Client::searchCards(const SearchCardsCriteria &criteria) const {

}

std::future<void> Client::revokeCard(const RevokeCardRequest &request) const {

}
