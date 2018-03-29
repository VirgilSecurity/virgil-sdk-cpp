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
#include <memory>

#include <TestConst.h>
#include <TestUtils.h>

#include <virgil/sdk/client/CardClient.h>

#include <virgil/sdk/client/models/RawCardContent.h>
#include <virgil/sdk/cards/ModelSigner.h>

using virgil::sdk::client::CardClient;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestUtils;
using virgil::sdk::client::models::RawCardContent;
using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::cards::ModelSigner;

TEST_CASE("test001_CreateCard", "[client]") {
//    TestConst consts;
//    TestUtils utils(consts);
//    auto crypto = std::make_shared<Crypto>();
//    ModelSigner modelSigner(crypto);
//    CardClient cardClient;
//
//    auto keyPair = crypto->generateKeyPair();
//
//    auto publicKeyData = crypto->exportPublicKey(keyPair.publicKey());
//
//    RawCardContent content("identity", publicKeyData, std::time(0));
//
//    auto snapshot = content.snapshot();
//
//    RawSignedModel rawCard(snapshot);
//
//    modelSigner.selfSign(rawCard, keyPair.privateKey());
//
//    std::string token = "token";
//    auto future = cardClient.publishCard(rawCard, token);
//
//    auto responseRawCard = future.get();
}

TEST_CASE("test002_CreateCardWithDataAndInfo", "[client]") {
    TestConst consts;
    TestUtils utils(consts);
}

TEST_CASE("test003_SearchCards", "[client]") {
    TestConst consts;
    TestUtils utils(consts);
}

TEST_CASE("test004_GetCard", "[client]") {
    TestConst consts;
    TestUtils utils(consts);

}
