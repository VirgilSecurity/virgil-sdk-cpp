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
#include <virgil/sdk/ServiceUri.h>
#include <virgil/sdk/io/Marshaller.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

const std::string VIRGIL_ACCESS_TOKEN =
    "eyJpZCI6IjFkNzgzNTA1LTk1NGMtNDJhZC1hZThjLWQyOGFiYmN"
    "hMGM1NyIsImFwcGxpY2F0aW9uX2NhcmRfaWQiOiIwNGYyY2Y2NS1iZDY2LTQ3N2EtOGFiZi1hMDAyYWY4Yj"
    "dmZWYiLCJ0dGwiOi0xLCJjdGwiOi0xLCJwcm9sb25nIjowfQ==.MIGZMA0GCWCGSAFlAwQCAgUABIGHMIGE"
    "AkAV1PHR3JaDsZBCl+6r/N5R5dATW9tcS4c44SwNeTQkHfEAlNboLpBBAwUtGhQbadRd4N4gxgm31sajEOJ"
    "IYiGIAkADCz+MncOO74UVEEot5NEaCtvWT7fIW9WaF6JdH47Z7kTp0gAnq67cPbS0NDUyovAqILjmOmg1zA"
    "L8A4+ii+zd";

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

        vsdk::ServicesHub virgilHub(VIRGIL_ACCESS_TOKEN, virgilUri);
        auto identityServiceVirgilCards = virgilHub.cards().getServiceCard(kIdentityServiceApplicationId);
        auto publicKeysServiceVirgilCards = virgilHub.cards().getServiceCard(kPublicKeyServiceApplicationId);
        auto privateKeysServiceVirgilCards = virgilHub.cards().getServiceCard(kPrivateKeyServiceApplicationId);

        vsdk::model::VirgilCard identityServiceVirgilCard = identityServiceVirgilCards.at(0);
        vsdk::model::VirgilCard publicKeysServiceVirgilCard = publicKeysServiceVirgilCards.at(0);
        vsdk::model::VirgilCard privateKeysServiceVirgilCard = privateKeysServiceVirgilCards.at(0);

        std::cout << "\n\nIdentity Service VirgilCard:"
                  << "\n";
        std::cout << vsdk::io::Marshaller<vsdk::model::VirgilCard>::toJson<4>(identityServiceVirgilCard) << "\n\n\n";

        std::cout << "Public Keys Service VirgilCard:"
                  << "\n";
        std::cout << vsdk::io::Marshaller<vsdk::model::VirgilCard>::toJson<4>(publicKeysServiceVirgilCard) << "\n\n\n";

        std::cout << "Private Keys Service VirgilCard:"
                  << "\n";
        std::cout << vsdk::io::Marshaller<vsdk::model::VirgilCard>::toJson<4>(privateKeysServiceVirgilCard) << "\n\n\n";

        virgilHub.identity().setServiceVirgilCard(identityServiceVirgilCard);
        virgilHub.publicKeys().setServiceVirgilCard(publicKeysServiceVirgilCard);
        virgilHub.cards().setServiceVirgilCard(publicKeysServiceVirgilCard);
        virgilHub.privateKeys().setServiceVirgilCard(privateKeysServiceVirgilCard);

    } catch (std::exception& exception) {
        std::cerr << exception.what() << "\n";
        return 1;
    }

    return 0;
}
