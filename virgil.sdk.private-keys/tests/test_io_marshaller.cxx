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

#include <string>

#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/privatekeys/io/Marshaller.h>
#include <virgil/sdk/privatekeys/util/JsonKey.h>
#include <virgil/sdk/privatekeys/model/PrivateKey.h>

#include <json.hpp>

#include "fakeit.hpp"

#include "helpers.h"
#include "fakeit_helpers.hpp"


using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::privatekeys::io::Marshaller;
using virgil::sdk::privatekeys::util::JsonKey;
using virgil::sdk::privatekeys::model::PrivateKey;

using json = nlohmann::json;

using namespace fakeit;


TEST_CASE("Private Key -> Json Private Key - FAILED:", "[virgil-sdk-private-keys]") {
    std::string encodePrivateKey = VirgilBase64::encode(expectedUserPrivateKeyData());

    json privateKeyJson = {
        { JsonKey::publicKeyId, USER_PUBLIC_KEY_ID },
        { JsonKey::privateKey, encodePrivateKey }
    };

    PrivateKey privateKey = Marshaller<PrivateKey>::fromJson(privateKeyJson.dump());

    REQUIRE( privateKey.publicKeyId() == USER_PUBLIC_KEY_ID );
    REQUIRE( privateKey.key() == expectedUserPrivateKeyData() );
}

TEST_CASE("Private Key <- Json Private Key - FAILED:", "[virgil-sdk-private-keys]") {
    PrivateKey privateKey;
    privateKey.key(expectedUserPrivateKeyData());
    privateKey.publicKeyId(USER_PUBLIC_KEY_ID);

    std::string privateKeyData =  Marshaller<PrivateKey>::toJson(privateKey);
    json privateKeyJson = json::parse(privateKeyData);

    std::string publicKeyId = privateKeyJson[JsonKey::publicKeyId];
    std::string keyData = privateKeyJson[JsonKey::privateKey];

    VirgilByteArray key = VirgilBase64::decode(keyData);

    REQUIRE( publicKeyId == USER_PUBLIC_KEY_ID );
    REQUIRE( key == expectedUserPrivateKeyData() );
}
