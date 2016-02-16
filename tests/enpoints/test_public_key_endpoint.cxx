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

#include <virgil/sdk/endpoints/PublicKeysEndpointUri.h>

using virgil::sdk::endpoints::PublicKeysEndpointUri;

TEST_CASE("std::string publicKeyGet(const std::string& publicKeyId) const", "class PublicKeysEndpointUri") {
    std::string publicKeyId = "456";
    REQUIRE(PublicKeysEndpointUri::publicKeyGet(publicKeyId) == "/v3/public-key/" + publicKeyId);
}

TEST_CASE("std::string publicKeyRevoke(const std::string& publicKeyId) const", "class PublicKeysEndpointUri") {
    std::string publicKeyId = "456";
    REQUIRE(PublicKeysEndpointUri::publicKeyRevoke(publicKeyId) == "/v3/public-key/" + publicKeyId);
}

TEST_CASE("std::string cardCreate() const", "class PublicKeysEndpointUri") {
    REQUIRE(PublicKeysEndpointUri::cardCreate() == "/v3/virgil-card");
}

TEST_CASE("std::string cardSearch() const", "class PublicKeysEndpointUri") {
    REQUIRE(PublicKeysEndpointUri::cardSearch() == "/v3/virgil-card/actions/search");
}

TEST_CASE("std::string cardSearchApp() const", "class PublicKeysEndpointUri") {
    REQUIRE(PublicKeysEndpointUri::cardSearchApp() == "/v3/virgil-card/actions/search/app");
}

TEST_CASE("std::string cardTrust(const std::string& cardId) const", "class PublicKeysEndpointUri") {
    std::string cardId = "123";
    REQUIRE(PublicKeysEndpointUri::cardTrust(cardId) == "/v3/virgil-card/" + cardId + "/actions/sign");
}

TEST_CASE("std::string cardUntrust(const std::string& cardId) const", "class PublicKeysEndpointUri") {
    std::string cardId = "123";
    REQUIRE(PublicKeysEndpointUri::cardUntrust(cardId) == "/v3/virgil-card/" + cardId + "/actions/unsign");
}

TEST_CASE("std::string cardRevoke(const std::string& cardId) const", "class PublicKeysEndpointUri") {
    std::string cardId = "123";
    REQUIRE(PublicKeysEndpointUri::cardRevoke(cardId) == "/v3/virgil-card/" + cardId);
}
