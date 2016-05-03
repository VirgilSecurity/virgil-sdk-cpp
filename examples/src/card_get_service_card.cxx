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

#include <iostream>
#include <string>
#include <stdexcept>
#include <vector>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/io/Marshaller.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

const std::string VIRGIL_ACCESS_TOKEN = "eyJpZCI6IjAwMmI1NzY0LTBmOTgtNDUyMC04YjA0LTc0ZmYxYjNl"
                                        "NmYyMSIsImFwcGxpY2F0aW9uX2NhcmRfaWQiOiIwMmJmOTIwYS1m"
                                        "MmI3LTQ1NzQtYTM1Ni0yYTY2MzVkOTdjMDUiLCJ0dGwiOi0xLCJj"
                                        "dGwiOi0xLCJwcm9sb25nIjowfQ==.MFgwDQYJYIZIAWUDBAICBQA"
                                        "ERzBFAiEA74ba/2MfdUu9ML2o9mVve5aC1U8rCGU1PY0u0v/luJY"
                                        "CIAhKKHF4u642FrtJ/aVX8XE4z1EGAs/FD707Fuh8SSnu";

const std::string VIRGIL_IDENTITY_SERVICE_URI_BASE = "https://identity-stg.virgilsecurity.com";
const std::string VIRGIL_PUBLIC_KEYS_SERVICE_URI_BASE = "https://keys-stg.virgilsecurity.com";
const std::string VIRGIL_PRIVATE_KEYS_SERVICE_URI_BASE = "https://private-stg.virgilsecurity.com";

const std::string kIdentityServiceApplicationId = "com.virgilsecurity.identity";
const std::string kPublicKeyServiceApplicationId = "com.virgilsecurity.keys";
const std::string kPrivateKeyServiceApplicationId = "com.virgilsecurity.private-keys";

int main() {
    try {
        vsdk::ServiceUri virgilUri(VIRGIL_IDENTITY_SERVICE_URI_BASE, VIRGIL_PUBLIC_KEYS_SERVICE_URI_BASE,
                                   VIRGIL_PRIVATE_KEYS_SERVICE_URI_BASE);

        vsdk::ServicesHub servicesHub(VIRGIL_ACCESS_TOKEN, virgilUri);
        auto identityServiceCards = servicesHub.card().searchGlobal(kIdentityServiceApplicationId, true);
        auto publicKeysServiceCards = servicesHub.card().searchGlobal(kPublicKeyServiceApplicationId, true);
        auto privateKeysServiceCards = servicesHub.card().searchGlobal(kPrivateKeyServiceApplicationId, true);

        vsdk::models::CardModel identityServiceCard = identityServiceCards.at(0);
        vsdk::models::CardModel publicKeysServiceCard = publicKeysServiceCards.at(0);
        vsdk::models::CardModel privateKeysServiceCard = privateKeysServiceCards.at(0);

        std::cout << "Identity Service Card:" << std::endl;
        std::cout << vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(identityServiceCard) << std::endl;

        std::cout << "Public Keys Service Card:" << std::endl;
        std::cout << vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(publicKeysServiceCard) << std::endl;

        std::cout << "Private Keys Service Card:" << std::endl;
        std::cout << vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(privateKeysServiceCard) << std::endl;

    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
        return 1;
    }

    return 0;
}
