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

#ifndef VIRGIL_SDK_SERVICES_HUB_H
#define VIRGIL_SDK_SERVICES_HUB_H

#include <memory>
#include <string>

#include <virgil/sdk/ServiceUri.h>
#include <virgil/sdk/ServiceCards.h>
#include <virgil/sdk/client/IdentityClient.h>
#include <virgil/sdk/client/PrivateKeysClient.h>
#include <virgil/sdk/client/PublicKeysClient.h>
#include <virgil/sdk/client/CardsClient.h>

namespace virgil {
namespace sdk {
    /**
     * @name Forward declaration
     */
    //@{
    class ServicesHubImpl;
    //@}
    /**
     * @brief Entry point for all Virgil Security Services
     */
    class ServicesHub {
    public:
        /**
         * @brief Configure services hub with lazy loaded Virgil Services Cards
         *
         * @param accessToken - provides an authenticated secure access to the Keys Service
         *                      and is passed with each API call @see
         * @param serviceUri - collection of Virgil Services URIs
         *
         * @note First you must create a free Virgil Security developer’s account by signing up.
         *       Once you have your account you can sign in and generate an access token for your application.
         */
        explicit ServicesHub(const std::string& accessToken,
                             const virgil::sdk::ServiceUri& baseServiceUri = virgil::sdk::ServiceUri());
        /**
         * @brief Configure services hub with known Virgil Services Cards
         *
         * @detail This constructor can be used if Virgil Cards of Virgil Services stored locally.
         *
         * @param accessToken - provides an authenticated secure access to the Keys Service
         *                      and is passed with each API call @see
         * @param serviceUri - collection of Virgil Services URIs
         * @param serviceCards - Virgil Cards provider for Virgil Services
         *
         * @note First you must create a free Virgil Security developer’s account by signing up.
         *       Once you have your account you can sign in and generate an access token for your application.
         */
        explicit ServicesHub(const std::string& accessToken, const virgil::sdk::ServiceCards& serviceCards,
                             const virgil::sdk::ServiceUri& baseServiceUri = virgil::sdk::ServiceUri());

        /**
         * @brief Return entrypoint for Virgil Identity Service
         */
        virgil::sdk::client::IdentityClient& identity();
        /**
         * @brief Return entrypoint for Virgil Cards Service
         */
        virgil::sdk::client::CardsClient& cards();
        /**
         * @brief Return entrypoint for Virgil Public Keys Service
         */
        virgil::sdk::client::PublicKeysClient& publicKeys();
        /**
         * @brief Return entrypoint for Virgil Private Keys Service
         */
        virgil::sdk::client::PrivateKeysClient& privateKeys();

    private:
        std::shared_ptr<ServicesHubImpl> impl_;
    };
}
}

#endif /* VIRGIL_SDK_VERSION_H */
