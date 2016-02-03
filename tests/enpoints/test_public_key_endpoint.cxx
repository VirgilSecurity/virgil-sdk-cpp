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
 * @file test_PublicKey_endpoint.cxx
 * @brief Covers "/PublicKey" endpoint.
 */

#include <string>

#include "../catch.hpp"

#include <virgil/sdk/endpoints//PublicKeysEndpointUri.h>

using virgil::sdk::endpoints::PublicKeysEndpointUri;


TEST_CASE("std::string publicKeyGet(const std::string& publicKeyId) const", "class PublicKeysEndpointUri") {
    std::string publicKeyId = "456";
    REQUIRE(
        PublicKeysEndpointUri::publicKeyGet(publicKeyId) == "/v3/public-key/" + publicKeyId
    );
}

TEST_CASE("std::string publicKeyRevoke(const std::string& publicKeyId) const", "class PublicKeysEndpointUri") {
    std::string publicKeyId = "456";    
    REQUIRE(
        PublicKeysEndpointUri::publicKeyRevoke(publicKeyId) == "/v3/public-key/" + publicKeyId);
}

TEST_CASE("std::string virgilCardCreate() const", "class PublicKeysEndpointUri") {
    REQUIRE(PublicKeysEndpointUri::virgilCardCreate() == "/v3/virgil-card");
}

TEST_CASE("std::string virgilCardSearch() const", "class PublicKeysEndpointUri") {
    REQUIRE(PublicKeysEndpointUri::virgilCardSearch() == "/v3/virgil-card/actions/search");
}

TEST_CASE("std::string virgilCardSearchApp() const", "class PublicKeysEndpointUri") {
    REQUIRE(PublicKeysEndpointUri::virgilCardSearchApp() == "/v3/virgil-card/actions/search/app");
}

TEST_CASE("std::string virgilCardTrust(const std::string& virgilCardId) const", "class PublicKeysEndpointUri") {
    std::string virgilCardId = "123";
    REQUIRE(
        PublicKeysEndpointUri::virgilCardTrust(virgilCardId) == "/v3/virgil-card/" + virgilCardId + "/actions/sign"
    );
}

TEST_CASE("std::string virgilCardUntrust(const std::string& virgilCardId) const", "class PublicKeysEndpointUri") {
    std::string virgilCardId = "123";
    REQUIRE(
        PublicKeysEndpointUri::virgilCardUntrust(virgilCardId) == "/v3/virgil-card/" + virgilCardId + "/actions/unsign"
    );
}

TEST_CASE("std::string virgilCardRevoke(const std::string& virgilCardId) const", "class PublicKeysEndpointUri") {
    std::string virgilCardId = "123";
    REQUIRE(
        PublicKeysEndpointUri::virgilCardRevoke(virgilCardId) == "/v3/virgil-card/" + virgilCardId
    );

}

