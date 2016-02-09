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
 * @brief Convert json <-> PrivateKey.
 */

#include "../catch.hpp"

#include "../helpers.h"

#include <virgil/sdk/io/Marshaller.h>


using json = nlohmann::json;

using virgil::sdk::model::PrivateKey;
using virgil::sdk::util::JsonKey;
using virgil::sdk::io::Marshaller;


TEST_CASE("PrivateKey -> Json PrivateKey - FAILED", "class Marshaller") {
    PrivateKey privateKey = virgil::test::getPrvKey();
    json trueJsonPrivateKey = virgil::test::getJsonPrvKey();

    // PrivateKey -> Json
    std::string testJsonPrivateKey = Marshaller<PrivateKey>::toJson<4>(privateKey);

    REQUIRE( trueJsonPrivateKey.dump(4) == testJsonPrivateKey );
}

TEST_CASE("Json PrivateKey -> PrivateKey - FAILED", "class Marshaller") {
    json jsonPrivateKey = virgil::test::getJsonPrvKey();

    // Json -> PrivateKey
    PrivateKey testPrivateKey = Marshaller<PrivateKey>::fromJson(jsonPrivateKey.dump(4));
    PrivateKey truePrivateKey = virgil::test::getPrvKey();

    REQUIRE( truePrivateKey.getVirgilCardId() == testPrivateKey.getVirgilCardId() );
    REQUIRE( truePrivateKey.getKeyStr() == testPrivateKey.getKeyStr() );
}