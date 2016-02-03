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
 * @brief Convert json <-> IdentityToken.
 */

#include "../catch.hpp"

#include <json.hpp>

#include <virgil/sdk/model/IdentityToken.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/io/Marshaller.h>

using json = nlohmann::json;

using virgil::sdk::model::IdentityToken;
using virgil::sdk::model::Identity;
using virgil::sdk::model::IdentityType;
using virgil::sdk::util::JsonKey;
using virgil::sdk::io::Marshaller;


TEST_CASE("IdentityToken -> Json IdentityToken - FAILED", "class Marshaller") {
    IdentityType type  = IdentityType::Email;
    std::string value = "user@virgilsecurity.com";

    Identity identity(value, type);

    std::string validationToken = "qwerty";

    IdentityToken identityToken(identity, validationToken);

    json trueJsonIdentityToken = {
        { JsonKey::type, virgil::sdk::model::toString(type) },
        { JsonKey::value, identityToken.getIdentity().getValue() },
        { JsonKey::validationToken, identityToken.getValidationToken() }
    };    

    // Identity -> Json
    std::string testJsonIdentityToken = Marshaller<IdentityToken>::toJson(identityToken);


    REQUIRE( trueJsonIdentityToken.dump() == testJsonIdentityToken );
}

TEST_CASE("Json IdentityToken -> IdentityToken - FAILED", "class Marshaller") {
    IdentityType type  = IdentityType::Email;
    std::string value = "user@virgilsecurity.com";
    Identity identity(value, type);

    std::string validationToken = "0KTUlHYk1CUUdCeXFHU000OUFnRUdDU3NrQXdNQ0NBRUJEUU9CZ2dBRUN"
            "hV3k5VVVVMDFWcjdQLzExWHpubk0vRAowTi9KODhnY0dMV3pYMGFLaGcxSjdib3B6RGV4b0QwaVl3alF";

    IdentityToken trueIdentityToken(identity, validationToken);

    json jsonIdentityToken = {
        { JsonKey::type, virgil::sdk::model::toString(type) },
        { JsonKey::value, trueIdentityToken.getIdentity().getValue() },
        { JsonKey::validationToken, trueIdentityToken.getValidationToken() }
    };

    // Json -> IdentityToken
    IdentityToken testIdentityToken = Marshaller<IdentityToken>::fromJson(jsonIdentityToken.dump());

    Identity trueIdentity = trueIdentityToken.getIdentity();
    Identity testIdentity = testIdentityToken.getIdentity();

    REQUIRE( trueIdentity.getType() == testIdentity.getType() );
    REQUIRE( trueIdentity.getValue() == testIdentity.getValue() );
    REQUIRE( trueIdentityToken.getValidationToken() == testIdentityToken.getValidationToken() );
}
