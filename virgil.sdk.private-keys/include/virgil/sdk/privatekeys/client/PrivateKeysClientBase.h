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

#ifndef VIRGIL_SDK_PRIVATE_KEYS_CLIENT_PK_CLIENT_H
#define VIRGIL_SDK_PRIVATE_KEYS_CLIENT_PK_CLIENT_H

#include <memory>

#include <virgil/sdk/privatekeys/client/AuthEndpointBase.h>
#include <virgil/sdk/privatekeys/client/ContainerEndpointBase.h>
#include <virgil/sdk/privatekeys/client/PrivateKeyEndpointBase.h>
#include <virgil/sdk/privatekeys/model/UserData.h>

namespace virgil { namespace sdk { namespace privatekeys { namespace client {
    /**
     * @brief Entrypoint for interacting with Virgil Private Keys Service PKI.
     */
    class PrivateKeysClientBase {
    public:
        /**
         * @brief Return "Authentication" endpoint§.
         */
        virtual AuthEndpointBase& auth() = 0;
        /**
         * @brief Return "Container" endpoint§.
         */
        virtual ContainerEndpointBase& container() = 0;
        /**
         * @brief Return "Private Key" endpoint§.
         */
        virtual PrivateKeyEndpointBase& privateKey() = 0;
        /**
         * @brief Get authentiction token from Virgil Security Private Keys service
         *        and set it for all endpoints.
         *
         * @param userData - added user data.
         * @param containerPassword - represents container password.
         * @throw KeysError - if request to service failed, or service return error code.
         */
        virtual void authenticate(const virgil::sdk::privatekeys::model::UserData& userData,
                const std::string& containerPassword) = 0;
        /**
         * @brief Set the authentication token for all endpoints.
         *
         * @param token - an authentication token.
         */
        virtual void authenticate(const std::string& token) = 0;
    };
}}}}

#endif /* VIRGIL_SDK_PRIVATE_KEYS_CLIENT_PK_CLIENT_H */
