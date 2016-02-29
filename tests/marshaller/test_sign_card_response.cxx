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

/**
 * @file test_identity_token_marshaller.cxx
 * @brief Convert json <-> CardSign.
 */

#include "../catch.hpp"

#include <json.hpp>

#include <virgil/sdk/models/CardSign.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/io/Marshaller.h>

#include "../helpers.h"

using json = nlohmann::json;

using virgil::sdk::models::CardSign;
using virgil::sdk::util::JsonKey;
using virgil::sdk::io::Marshaller;

TEST_CASE("CardSign -> Json ValidatedIdentity - FAILED", "class Marshaller") {
    CardSign cardSign = virgil::test::getCardSign();
    // CardSign -> Json
    std::string testJsonCardSign = Marshaller<CardSign>::toJson<4>(cardSign);
    REQUIRE(virgil::test::getJsonCardSign().dump(4) == testJsonCardSign);
}

TEST_CASE("Json CardSign -> CardSign - FAILED", "class Marshaller") {
    json jsonCardSign = virgil::test::getJsonCardSign();
    // Json -> CardSign
    CardSign testCardSign = Marshaller<CardSign>::fromJson(jsonCardSign.dump(4));
    REQUIRE(virgil::test::getCardSign() == testCardSign);
}
