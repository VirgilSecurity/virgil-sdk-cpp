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

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/client/IdentityClient.h>
#include <virgil/sdk/client/PrivateKeyClient.h>
#include <virgil/sdk/client/PublicKeyClient.h>
#include <virgil/sdk/client/CardClient.h>
#include <virgil/sdk/ServiceUri.h>

using virgil::crypto::VirgilByteArray;

using virgil::sdk::ServicesHub;
using virgil::sdk::ServiceUri;
using virgil::sdk::model::Card;
using virgil::sdk::client::IdentityClient;
using virgil::sdk::client::PrivateKeyClient;
using virgil::sdk::client::PublicKeyClient;
using virgil::sdk::client::CardClient;

const std::string kKeyServiceAppId = "com.virgilsecurity.keys";
const std::string kIdentityServiceAppId = "com.virgilsecurity.identity";
const std::string kPrivateKeyServiceAppId = "com.virgilsecurity.private-keys";

namespace virgil {
namespace sdk {
    class ServicesHubImpl {
    public:
        std::shared_ptr<CardClient> cardClient;
        std::shared_ptr<IdentityClient> identityClient;
        std::shared_ptr<PublicKeyClient> publicKeyClient;
        std::shared_ptr<PrivateKeyClient> privateKeyClient;
    };
}
}

static Card getServiceCard(const CardClient& cardClient, const std::string& serviceApplicationId) {
    auto cards = cardClient.searchApp(serviceApplicationId, true);
    if (!cards.empty()) {
        return cards.front();
    } else {
        throw std::runtime_error("CardClient: Service Card not found on Virgil Keys Service.");
    }
}

ServicesHub::ServicesHub(const std::string& accessToken, const ServiceUri& baseServiceUri)
        : impl_(std::make_shared<virgil::sdk::ServicesHubImpl>()) {
    // Init CardClient first to use it for loading Virgil Cards for other services.
    // CardClient can download it's Virgil Card by itself
    impl_->cardClient = std::make_shared<CardClient>(accessToken, baseServiceUri.getPublicKeyService());
    impl_->identityClient =
        std::make_shared<IdentityClient>(accessToken, baseServiceUri.getIdentityService(), [this]() -> Card {
            return getServiceCard(*impl_->cardClient, kIdentityServiceAppId);
        });
    impl_->publicKeyClient =
        std::make_shared<PublicKeyClient>(accessToken, baseServiceUri.getPublicKeyService(), [this]() -> Card {
            return getServiceCard(*impl_->cardClient, kKeyServiceAppId);
        });
    impl_->privateKeyClient =
        std::make_shared<PrivateKeyClient>(accessToken, baseServiceUri.getPrivateKeyService(), [this]() -> Card {
            return getServiceCard(*impl_->cardClient, kPrivateKeyServiceAppId);
        });
}

ServicesHub::ServicesHub(const std::string& accessToken, const virgil::sdk::ServiceCards& serviceCards,
                         const virgil::sdk::ServiceUri& baseServiceUri) {
    impl_->cardClient = std::make_shared<CardClient>(accessToken, baseServiceUri.getPublicKeyService(),
                                                     [&]() -> Card { return serviceCards.loadKeyServiceCard(); });
    impl_->identityClient =
        std::make_shared<IdentityClient>(accessToken, baseServiceUri.getIdentityService(),
                                         [&]() -> Card { return serviceCards.loadIdentityServiceCard(); });
    impl_->publicKeyClient = std::make_shared<PublicKeyClient>(
        accessToken, baseServiceUri.getPublicKeyService(), [&]() -> Card { return serviceCards.loadKeyServiceCard(); });
    impl_->privateKeyClient =
        std::make_shared<PrivateKeyClient>(accessToken, baseServiceUri.getPrivateKeyService(),
                                           [&]() -> Card { return serviceCards.loadPrivateKeyServiceCard(); });
}

CardClient& ServicesHub::card() {
    return *(impl_->cardClient);
}

IdentityClient& ServicesHub::identity() {
    return *(impl_->identityClient);
}

PrivateKeyClient& ServicesHub::privateKey() {
    return *(impl_->privateKeyClient);
}

PublicKeyClient& ServicesHub::publicKey() {
    return *(impl_->publicKeyClient);
}
