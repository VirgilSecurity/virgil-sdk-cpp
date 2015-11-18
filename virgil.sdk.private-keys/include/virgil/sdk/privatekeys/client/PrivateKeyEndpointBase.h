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

#ifndef VIRGIL_SDK_PRIVATE_KEYS_PRIVATE_KEY_ENDPOINT_BASE_H
#define VIRGIL_SDK_PRIVATE_KEYS_PRIVATE_KEY_ENDPOINT_BASE_H

#include <string>
#include <vector>

#include <virgil/sdk/privatekeys/client/CredentialsExt.h>
#include <virgil/sdk/privatekeys/model/PrivateKey.h>

namespace virgil { namespace sdk { namespace privatekeys { namespace client {
    /**
    * @brief Endpoint "/private-key" of the Virgil Private Keys Service API.
    */
    class PrivateKeyEndpointBase {
    public:
        /**
         * @brief Create a Private Key inside the Container Object.
         *
         * Load an given Private Key into the Private Keys service and associate it with the existing Container.
         * @param credentials - user's credentials.
         * @param pass - user's password. if container type easy: pass must be equal container pass.
         * @throw KeysError - if request to service failed, or service return error code.
         *
         * @note Require authentication.
         * @see PrivateKeysClient::authenticate()
         *
         */
        virtual void add(const virgil::sdk::privatekeys::client::CredentialsExt& credentials,
                const std::string& pass) const = 0;
        /**
         * @brief Get private key by its UUID.
         *
         * @param publicKeyId - public key UUID.
         * @return Private key.
         * @throw KeysError - if request to service failed, or service return error code.
         *
         * @note Require authentication.
         * @see PrivateKeysClient::authenticate()
         */
        virtual virgil::sdk::privatekeys::model::PrivateKey get(const std::string& publicKeyId,
                const std::string& pass) const = 0;
        /**
         * @brief Delete private key associated with given user's credentials.
         *
         * @param credentials - user's credentials.
         * @throw KeysError - if request to service failed, or service return error code.
         *
         * @note Require authentication.
         * @see PrivateKeysClient::authenticate()
         */
        virtual void del(const CredentialsExt &credentials) const = 0;
    };
}}}}

#endif /* VIRGIL_SDK_PRIVATE_KEYS_PRIVATE_KEY_ENDPOINT_BASE_H */
