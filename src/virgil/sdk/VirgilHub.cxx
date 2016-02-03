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
#include <vector>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/VirgilHub.h>
#include <virgil/sdk/client/IdentityClient.h>
#include <virgil/sdk/client/PrivateKeysClient.h>
#include <virgil/sdk/client/PublicKeysClient.h>
#include <virgil/sdk/client/VirgilCardsClient.h>
#include <virgil/sdk/VirgilUri.h>

using virgil::crypto::VirgilByteArray;

using virgil::sdk::VirgilHub;
using virgil::sdk::client::IdentityClientBase;
using virgil::sdk::client::IdentityClient;
using virgil::sdk::client::PrivateKeysClientBase;
using virgil::sdk::client::PrivateKeysClient;
using virgil::sdk::client::PublicKeysClientBase;
using virgil::sdk::client::PublicKeysClient;
using virgil::sdk::client::VirgilCardsClientBase;
using virgil::sdk::client::VirgilCardsClient;
using virgil::sdk::model::VirgilCard;
using virgil::sdk::VirgilUri;


const std::string kIdentityServiceApplicationId = "com.virgilsecurity.identity";
const std::string kPublicKeyServiceApplicationId = "com.virgilsecurity.keys";
const std::string kPrivateKeyServiceApplicationId = "com.virgilsecurity.private-keys";


namespace virgil { namespace sdk {
    class VirgilHubClientImpl {
    public:
        explicit VirgilHubClientImpl(const std::string& accessToken,
                const VirgilUri& baseServiceUri)
            : 
              identityClient(accessToken, baseServiceUri.getIdentityService() ),
              publicKeysClient(accessToken, baseServiceUri.getPublicKeyService() ),
              virgilCardsClient(accessToken, baseServiceUri.getPublicKeyService() ),
              privateKeysClient(accessToken, baseServiceUri.getPrivateKeyService() ) {

        }

    public:
        IdentityClient identityClient;
        PublicKeysClient publicKeysClient;
        VirgilCardsClient virgilCardsClient;
        PrivateKeysClient privateKeysClient;

    };
}}

VirgilHub::VirgilHub(const std::string& accessToken, const VirgilUri& baseServiceUri)
    : 
      accessToken_(accessToken),
      virgilUri_(baseServiceUri),
      impl_( std::make_shared<virgil::sdk::VirgilHubClientImpl>(accessToken_, virgilUri_) ) {

}

IdentityClientBase& VirgilHub::identity() {
    return impl_->identityClient;
}

PrivateKeysClientBase& VirgilHub::privateKeys() {
    return impl_->privateKeysClient;
}

PublicKeysClientBase& VirgilHub::publicKeys() {
    return impl_->publicKeysClient;
}

VirgilCardsClientBase& VirgilHub::cards() {
    return impl_->virgilCardsClient;
}

void VirgilHub::loadServicePublicKeys() {
    auto identityServiceVirgilCards = impl_->virgilCardsClient.getServiceCard(kIdentityServiceApplicationId);
    auto publicKeysServiceVirgilCards = impl_->virgilCardsClient.getServiceCard(kPublicKeyServiceApplicationId);
    auto privateKeysServiceVirgilCards = impl_->virgilCardsClient.getServiceCard(kPrivateKeyServiceApplicationId);

    auto identityServiceVirgilCard = identityServiceVirgilCards.at(0);
    auto publicKeysServiceVirgilCard = publicKeysServiceVirgilCards.at(0);
    auto privateKeysServiceVirgilCard = privateKeysServiceVirgilCards.at(0);

    impl_->identityClient.setServiceVirgilCard(identityServiceVirgilCard);
    impl_->publicKeysClient.setServiceVirgilCard(publicKeysServiceVirgilCard);
    impl_->virgilCardsClient.setServiceVirgilCard(publicKeysServiceVirgilCard);
    impl_->privateKeysClient.setServiceVirgilCard(privateKeysServiceVirgilCard);
}
