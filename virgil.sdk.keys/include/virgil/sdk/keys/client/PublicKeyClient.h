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

#ifndef VIRGIL_SDK_KEYS_CLIENT_PUBLIC_KEY_CLIENT_H
#define VIRGIL_SDK_KEYS_CLIENT_PUBLIC_KEY_CLIENT_H

#include <string>
#include <vector>

#include <virgil/sdk/keys/client/EndpointClient.h>
using virgil::sdk::keys::client::EndpointClient;

#include <virgil/sdk/keys/model/Account.h>
using virgil::sdk::keys::model::Account;
#include <virgil/sdk/keys/model/PublicKey.h>
using virgil::sdk::keys::model::PublicKey;
#include <virgil/sdk/keys/model/UserData.h>
using virgil::sdk::keys::model::UserData;

namespace virgil { namespace sdk { namespace keys { namespace client {
    /**
     * @brief Endpoint "/public-key" to the Virgil Public Keys Service (API).
     */
    class PublicKeyClient : public EndpointClient {
    public:
        /**
         * @brief Inherit base class constructor.
         */
        using EndpointClient::EndpointClient;
        /**
         * @brief Add public key to the account.
         * @param publicKey - public key to add.
         * @param userData - user data associated with public key.
         * @param accountId - target account GUID.
         * @note If parameter @link accountId @endlink is omitted, new account will be created.
         */
        virtual PublicKey add(const std::vector<unsigned char>& publicKey,
                const std::vector<UserData>& userData, const std::string& accountId = "") const = 0;
        /**
         * @brief Get public key by identifier.
         * @param publicKeyId - public key GUID.
         */
        virtual PublicKey get(const std::string& publicKeyId) const = 0;
        /**
         * @brief Search associated with given user public keys.
         * @param userId - user unique identifier: email, phone, fax, application, etc.
         * @return Found public keys associated with given user.
         */
        virtual std::vector<Account> search(const std::string& userId) const = 0;
    };
}}}}

#endif /* VIRGIL_SDK_KEYS_CLIENT_PUBLIC_KEY_CLIENT_H */
