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

#include <iostream>
#include <string>

#include "../catch.hpp"

#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/io/Marshaller.h>

#include "../helpers.h"

using json = nlohmann::json;

using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::models::PublicKeyModel;
using virgil::sdk::util::JsonKey;
using virgil::sdk::io::Marshaller;

TEST_CASE("PublicKey -> Json PublicKeyModel - FAILED", "class Marshaller") {
    PublicKeyModel publicKey = virgil::test::getPublicKey();
    // PublicKeyModel -> Json
    std::string testJsonPublicKey = Marshaller<PublicKeyModel>::toJson<4>(publicKey);

    REQUIRE(virgil::test::getJsonPublicKey().dump(4) == testJsonPublicKey);
}

TEST_CASE("Json PublicKeyModel -> PublicKeyModel - FAILED", "class Marshaller") {
    json jsonPublicKey = virgil::test::getJsonPublicKey();
    // Json -> PublicKey
    PublicKeyModel testPublicKey = Marshaller<PublicKeyModel>::fromJson(jsonPublicKey.dump());

    // Beutiful!!!
    // std::cout << testPublicKey.getKey() << "\n\n";

    // Real world (*
    // std::cout << VirgilBase64::encode( testPublicKey.getKey() )<< "\n\n";

    REQUIRE(virgil::test::getPublicKey() == testPublicKey);
}
