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
 * @brief Convert json <-> PublicKey.
 */

#include <string>

#include "../catch.hpp"

#include "../helpers.h"

#include <virgil/sdk/io/Marshaller.h>

using json = nlohmann::json;

using virgil::sdk::model::PublicKey;
using virgil::sdk::util::JsonKey;
using virgil::sdk::io::Marshaller;


TEST_CASE("PublicKey -> Json PublicKey - FAILED", "class Marshaller") {
    PublicKey publicKey = virgil::test::getPubKey();

    json trueJsonPublicKey = {
        { JsonKey::id, publicKey.getId() },
        { JsonKey::publicKey, publicKey.getKeyBase64() },
        { JsonKey::createdAt, publicKey.getCreatedAt() }
    };

    // Identity -> Json
    std::string testJsonPublicKey = Marshaller<PublicKey>::toJson<4>(publicKey);

    REQUIRE( trueJsonPublicKey.dump(4) == testJsonPublicKey );
}

TEST_CASE("Json PublicKey -> PublicKey - FAILED", "class Marshaller") {
    json jsonPublicKey = virgil::test::getJsonPubKey();

    // Json -> PublicKey
    PublicKey testPublicKey = Marshaller<PublicKey>::fromJson(jsonPublicKey.dump());
    PublicKey truePublicKey = virgil::test::getPubKey();

    REQUIRE( truePublicKey.getId() == testPublicKey.getId() );
    REQUIRE( truePublicKey.getCreatedAt() == testPublicKey.getCreatedAt() );
    REQUIRE( truePublicKey.getKey() == testPublicKey.getKey() );
}
