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
 * @brief Convert json <-> ValidationToken.
 */

#include "../catch.hpp"

#include <json.hpp>

#include <virgil/sdk/model/ValidationToken.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/io/Marshaller.h>

using json = nlohmann::json;

using virgil::sdk::model::ValidationToken;
using virgil::sdk::model::Identity;
using virgil::sdk::model::IdentityType;
using virgil::sdk::util::JsonKey;
using virgil::sdk::io::Marshaller;


TEST_CASE("ValidationToken -> Json ValidationToken - FAILED", "class Marshaller") {
    std::string value = "user@virgilsecurity.com";
    IdentityType type  = IdentityType::Email;

    Identity identity(value, type);
    std::string token = "qwerty";

    ValidationToken validationToken(identity, token);

    json trueJsonValidationToken = {
        { JsonKey::type, virgil::sdk::model::toString(type) },
        { JsonKey::value, validationToken.getIdentity().getValue() },
        { JsonKey::validationToken, validationToken.getToken() }
    };

    // ValidationToken -> Json
    std::string testJsonValidationToken = Marshaller<ValidationToken>::toJson(validationToken);

    REQUIRE( trueJsonValidationToken.dump() == testJsonValidationToken );
}

TEST_CASE("Json ValidationToken -> ValidationToken - FAILED", "class Marshaller") {
    std::string value = "user@virgilsecurity.com";
    IdentityType type  = IdentityType::Email;
    Identity identity(value, type);

    std::string validationToken = "0KTUlHYk1CUUdCeXFHU000OUFnRUdDU3NrQXdNQ0NBRUJEUU9CZ2dBRUN"
            "hV3k5VVVVMDFWcjdQLzExWHpubk0vRAowTi9KODhnY0dMV3pYMGFLaGcxSjdib3B6RGV4b0QwaVl3alF";

    ValidationToken trueValidationToken(identity, validationToken);

    json jsonValidationToken = {
        { JsonKey::type, virgil::sdk::model::toString(type) },
        { JsonKey::value, trueValidationToken.getIdentity().getValue() },
        { JsonKey::validationToken, trueValidationToken.getToken() }
    };

    // Json -> ValidationToken
    ValidationToken testValidationToken = Marshaller<ValidationToken>::fromJson(jsonValidationToken.dump());

    Identity trueIdentity = trueValidationToken.getIdentity();
    Identity testIdentity = testValidationToken.getIdentity();

    REQUIRE( trueIdentity.getType() == testIdentity.getType() );
    REQUIRE( trueIdentity.getValue() == testIdentity.getValue() );
    REQUIRE( trueValidationToken.getToken() == testValidationToken.getToken() );
}
