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

#ifndef VIRGIL_SDK_PUBLIC_KEY_CLIENT_H
#define VIRGIL_SDK_PUBLIC_KEY_CLIENT_H

#include <virgil/sdk/client/Client.h>

#include <virgil/sdk/Credentials.h>
#include <virgil/sdk/model/ValidatedIdentity.h>
#include <virgil/sdk/model/Card.h>
#include <virgil/sdk/model/PublicKey.h>
#include <virgil/sdk/http/Response.h>

namespace virgil {
namespace sdk {
    namespace client {
        /**
         * @brief Endpoint "/public-key" to the Virgil Keys Service
         *
         * Public Key entity is an entity that is implicitly created by using POST /virgil-card endpoint.
         * A Public Key entity contains the associated Virgil Cards entities, that are available via signed version
         *      of the GET /public-key/{public-key-id} endpoint.
         *
         * @see virgil::sdk::client::CardClient::create()
         * @see virgil::sdk::client::CardClient::get()
         */
        class PublicKeyClient : public Client {
        public:
            using Client::Client;
            /**
             * @brief Returns Public Key by it's identifier
             *
             * @param publicKeyId - Public Key identifier
             * @return Pubic Key
             */
            virgil::sdk::model::PublicKey get(const std::string& publicKeyId);
            /**
             * @brief Revoke a Public Key
             *
             * To revoke the Public Key it's mandatory to pass validation tokens obtained on Virgil Identity service,
             *     for all confirmed Virgil Cards for this Public Key.
             *
             * @param publicKeyId - Public Key identifier to be revoked
             * @param validatedIdentitys - list of validated identities that was associated with given Public Key
             * @param cardId - one of the Virgil Cards identifier that associated with given Public Key
             * @param credentials - Private Key associated with given Virgil Card
             */
            void revoke(const std::string& publicKeyId,
                        const std::vector<virgil::sdk::model::ValidatedIdentity> validatedIdentitys,
                        const std::string& cardId, const virgil::sdk::Credentials& credentials);
        };
    }
}
}

#endif /* VIRGIL_SDK_PUBLIC_KEY_CLIENT_H */
