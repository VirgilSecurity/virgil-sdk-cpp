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

#ifndef VIRGIL_SDK_PRIVATE_KEY_CLIENT_H
#define VIRGIL_SDK_PRIVATE_KEY_CLIENT_H

#include <virgil/sdk/client/Client.h>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/Credentials.h>
#include <virgil/sdk/model/ValidatedIdentity.h>
#include <virgil/sdk/model/PrivateKey.h>
#include <virgil/sdk/model/Card.h>
#include <virgil/sdk/http/Response.h>

namespace virgil {
namespace sdk {
    namespace client {
        /**
         * @brief Entrypoint for interacting with Virgil Private Keys Service
         *
         * General statements:
         *
         * 1. Make sure that you have registered and confirmed your account for the Public Keys Service.
         * 2. Make sure that you have a public/private key pair and you have already uploaded the public key
         *        to the Public Keys Service.
         * 3. Make sure that you have your private key on local machine.
         * 4. Make sure that you have registered an application at
         *        [Virgil Security, Inc](https://developer.virgilsecurity.com/account/signup).
         */
        class PrivateKeyClient : public Client {
        public:
            using Client::Client;
            /**
             * @brief Load Private Key into the Private Keys Service storage
             *
             * @param cardId - Virgil Card identifier that associated to the given Private Key
             * @param credentials - Private Key to be uploaded
             */
            void add(const std::string& cardId, const Credentials& credentials);
            /**
             * @brief Get an existing private key
             *
             * @param cardId - Virgil Card identifier that associated requested Private Key
             * @param validatedIdentity - validated identity that connected with Virgil Card
             *                            which associated with a requested Private Key
             *
             * @return Requested Private Key
             * @see virgil::sdk::client::IdentityService - to get validated identity
             */
            virgil::sdk::model::PrivateKey get(const std::string& cardId,
                                               const virgil::sdk::model::ValidatedIdentity& validatedIdentity);
            /**
             * @brief Delete a Private Key
             *
             * @param cardId -  Virgil Card identifier that associated deleted Private Key
             * @param credentials - Private Key to be deleted
             */
            void del(const std::string& cardId, const Credentials& credentials);
        };
    }
}
}

#endif /* VIRGIL_SDK_PRIVATE_KEY_CLIENT_H */
