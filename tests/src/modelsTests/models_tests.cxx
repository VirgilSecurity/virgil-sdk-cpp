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

#include <catch.hpp>

#include <thread>

#include <TestConst.h>
#include <TestUtils.h>

#include <virgil/sdk/client/Client.h>
#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/models/ClientCommon.h>
#include <virgil/sdk/client/CardValidator.h>

#include <virgil/sdk/util/Memory.h>

using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::requests::RevokeCardRequest;
using virgil::sdk::client::models::CardRevocationReason;
using virgil::sdk::client::CardValidator;
using virgil::sdk::VirgilBase64;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestUtils;

TEST_CASE("test001_CardImportExport", "[models]") {
    TestUtils utils((TestConst()));

    std::unordered_map<std::string, std::string> data;
    data["some_random_key1"] = "some_random_data1";
    data["some_random_key2"] = "some_random_data2";

    auto createCardRequest = utils.instantiateCreateCardRequest(data, "mac", "very_good_mac");

    auto request = createCardRequest.exportAsString();

    auto importedRequest = CreateCardRequest::importFromString(request);

    REQUIRE(utils.checkCreateCardRequestEquality(createCardRequest, importedRequest));
}

TEST_CASE("test002_RevokeCardImportExport", "[models]") {
    TestUtils utils((TestConst()));

    std::unordered_map<std::string, std::string> data;
    data["some_random_key1"] = "some_random_data1";
    data["some_random_key2"] = "some_random_data2";

    auto revokeCardRequest = RevokeCardRequest::createRequest("testId", CardRevocationReason::unspecified);

    auto request = revokeCardRequest.exportAsString();

    auto importedRequest = RevokeCardRequest::importFromString(request);

    REQUIRE(utils.checkRevokeCardRequestEquality(revokeCardRequest, importedRequest));
}

TEST_CASE("test003_CardImportExport", "[models]") {
    TestConst consts;
    TestUtils utils((TestConst()));

    auto card = utils.instantiateCard();

    auto cardStr = card.exportAsString();

    auto importedCard = Card::importFromString(cardStr);

    auto validator = std::make_unique<CardValidator>(utils.crypto());
    validator->addVerifier(consts.applicationId(), VirgilBase64::decode(consts.applicationPublicKeyBase64()));
    REQUIRE(validator->verifiers().size() == 2);

    REQUIRE(utils.checkCardEquality(card, importedCard));
}
