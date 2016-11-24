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

#include <TestConst.h>
#include <TestUtils.h>

#include <virgil/sdk/client/models/requests/CreateCardRequest.h>
#include <virgil/sdk/client/Client.h>

using virgil::sdk::client::Client;
using virgil::sdk::client::ClientInterface;
using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestUtils;

TEST_CASE("test001_CreateCard", "[client]") {
    auto client = Client("AT.931f8eb623be4e4709cbc241bfc89dde3a518527faccf2e1da7f9bd1a71fe78b",
                         "https://cards.virgilsecurity.com/");
    Crypto crypto;

    TestConst consts;
    TestUtils utils(crypto, consts);

    auto createCardRequest = utils.instantiateCreateCardRequest();

    auto future = client.createCard(createCardRequest);

    auto card = future.get();
}

TEST_CASE("test004_GetCard", "[client]") {
    auto client = Client("AT.931f8eb623be4e4709cbc241bfc89dde3a518527faccf2e1da7f9bd1a71fe78b",
                                    "https://cards.virgilsecurity.com/");

    Crypto crypto;

    TestConst consts;
    TestUtils utils(crypto, consts);

//    auto future = client.getCard("8045d25cb37e00e979cecd39b4552d4befed707dc3d69ca6ca34f8341869f43f");
//
//    auto card = future.get();
}
