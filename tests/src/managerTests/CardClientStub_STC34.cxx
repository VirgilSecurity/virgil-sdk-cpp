/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#include <stubs/CardClientStub_STC34.h>
#include <virgil/sdk/client/models/RawSignedModel.h>

using virgil::sdk::test::stubs::CardClientStub_STC34;
using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::client::models::GetCardResponse;

CardClientStub_STC34::CardClientStub_STC34() {
    testData_ = virgil::sdk::test::TestData();
}

std::future<RawSignedModel> CardClientStub_STC34::publishCard(const RawSignedModel &model,
                                                                      const std::string &token) const {
    std::promise<RawSignedModel> p;
    p.set_value(RawSignedModel::importFromBase64EncodedString(testData_.dict()["STC-34.as_string"]));

    return p.get_future();
}

std::future<GetCardResponse> CardClientStub_STC34::getCard(const std::string &cardId,
                                                                   const std::string &token) const {
    std::promise<GetCardResponse> p;
    auto rawCard = RawSignedModel::importFromBase64EncodedString(testData_.dict()["STC-34.as_string"]);
    p.set_value(GetCardResponse(rawCard, false));

    return p.get_future();
}

std::future<std::vector<RawSignedModel>> CardClientStub_STC34::searchCards(const std::string &identity,
                                                                                   const std::string &token) const {
    std::promise<std::vector<RawSignedModel>> p;
    p.set_value({RawSignedModel::importFromBase64EncodedString(testData_.dict()["STC-34.as_string"])});

    return p.get_future();
}