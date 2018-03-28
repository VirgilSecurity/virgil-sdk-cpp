/**
 * Copyright (C) 2018 Virgil Security Inc.
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

#include <unordered_map>
#include <virgil/sdk/client/CardClient.h>
#include <virgil/sdk/http/ClientRequest.h>
#include <virgil/sdk/endpoints/CardEndpointUri.h>
#include <virgil/sdk/client/models/serialization/JsonSerializer.h>
#include <virgil/sdk/client/models/serialization/JsonDeserializer.h>
#include <virgil/sdk/http/Connection.h>
#include <virgil/sdk/http/Response.h>
#include <virgil/sdk/VirgilSdkError.h>
#include <virgil/sdk/client/models/errors/VirgilError.h>
#include <virgil/sdk/util/JsonUtils.h>

using virgil::sdk::client::CardClient;
using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::http::ClientRequest;
using virgil::sdk::endpoints::CardEndpointUri;
using virgil::sdk::client::models::serialization::JsonSerializer;
using virgil::sdk::client::models::serialization::JsonDeserializer;
using virgil::sdk::http::Connection;
using virgil::sdk::http::Response;
using virgil::sdk::client::models::errors::Error;
using virgil::sdk::client::models::errors::VirgilError;
using virgil::sdk::util::JsonUtils;
using virgil::sdk::client::models::GetCardResponse;

const std::string CardClient::xVirgilIsSuperseededKey = "x-virgil-is-superseeded";

CardClient::CardClient(const std::string &serviceUrl)
: serviceUrl_(serviceUrl) {}

const std::string& CardClient::serviceUrl() const { return serviceUrl_; }

std::future<RawSignedModel> CardClient::publishCard(const RawSignedModel &model, const std::string &token) const {
    auto future = std::async([=]{
        ClientRequest httpRequest = ClientRequest(token);
        httpRequest
                .post()
                .baseAddress(this->serviceUrl_)
                .endpoint(CardEndpointUri::publish())
                .body(JsonSerializer<RawSignedModel>::toJson(model));

        Connection connection;
        Response response = connection.send(httpRequest);

        if (response.fail()) {
            auto error = this->parseError(response);
            throw make_error(VirgilSdkError::ServiceQueryFailed, error.errorMsg());
        }

        auto rawCard = JsonDeserializer<RawSignedModel>::fromJsonString(response.body());

        return rawCard;
    });

    return future;
}

std::future<std::vector<RawSignedModel>> CardClient::searchCards(const std::string &identity,
                                                                 const std::string &token) const {
    auto future = std::async([=]{
        ClientRequest httpRequest = ClientRequest(token);
        std::unordered_map<std::string, std::string> bodyMap = { std::make_pair("identity", identity) };
        httpRequest
                .post()
                .baseAddress(this->serviceUrl_)
                .endpoint(CardEndpointUri::search())
                .body(JsonUtils::unorderedMapToJson(bodyMap).dump());

        Connection connection;
        Response response = connection.send(httpRequest);

        if (response.fail()) {
            auto error = this->parseError(response);
            throw make_error(VirgilSdkError::ServiceQueryFailed, error.errorMsg());
        }

        auto rawCards = JsonDeserializer<std::vector<RawSignedModel>>::fromJsonString(response.body());

        return rawCards;
    });

    return future;
}

std::future<GetCardResponse> CardClient::getCard(const std::string &cardId, const std::string &token) const {
    auto future = std::async([=]{
        ClientRequest httpRequest = ClientRequest(token);
        httpRequest
                .get()
                .baseAddress(this->serviceUrl_)
                .endpoint(CardEndpointUri::get(cardId));

        Connection connection;
        Response response = connection.send(httpRequest);

        if (response.fail()) {
            auto error = this->parseError(response);
            throw make_error(VirgilSdkError::ServiceQueryFailed, error.errorMsg());
        }

        auto rawCard = JsonDeserializer<RawSignedModel>::fromJsonString(response.body());

        bool isOutdated = false;
        if (response.header()[CardClient::xVirgilIsSuperseededKey] == "true")
            isOutdated = true;

        auto getCardResponse = GetCardResponse(rawCard, isOutdated);

        return getCardResponse;
    });

    return future;
}