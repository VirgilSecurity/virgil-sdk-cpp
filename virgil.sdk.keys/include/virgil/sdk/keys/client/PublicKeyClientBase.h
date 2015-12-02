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

#ifndef VIRGIL_SDK_KEYS_PUBLIC_KEY_CLIENT_BASE_H
#define VIRGIL_SDK_KEYS_PUBLIC_KEY_CLIENT_BASE_H

#include <string>
#include <vector>

#include <virgil/sdk/keys/client/Credentials.h>
#include <virgil/sdk/keys/client/CredentialsExt.h>
#include <virgil/sdk/keys/model/PublicKey.h>
#include <virgil/sdk/keys/model/UserData.h>


namespace virgil { namespace sdk { namespace keys { namespace client {
    /**
     * @brief Endpoint "/public-key" to the Virgil Public Keys Service (API).
     */
    class PublicKeyClientBase {
    public:
        /**
         * @brief Add public key to the account.
         *
         * The Virgil Account will be created implicitly when the first Public Key uploaded.
         *     The application can get the information about Public Keys created only for current application.
         *     When application uploads new Public Key and there is an Account created
         *     for another application with the same UDID, the Public Key will be implicitly
         *     attached to the existing Account instance.
         *
         * @param key - public key to add.
         * @param userData - user data associated with public key.
         * @param credentials - user's credentials.
         * @return Public key and user's data associated with it.
         * @throw KeysError - if request to service failed, or service return error code.
         */
        virtual virgil::sdk::keys::model::PublicKey add(const std::vector<unsigned char>& key,
                const std::vector<virgil::sdk::keys::model::UserData>& userData,
                const Credentials& credentials) const = 0;
        /**
         * @brief Get public key by its UUID.
         * @param publicKeyId - public key UUID.
         * @return Public key.
         * @throw KeysError - if request to service failed, or service return error code.
         */
        virtual virgil::sdk::keys::model::PublicKey get(const std::string& publicKeyId) const = 0;
        /**
         * @brief Replace stale public key with a new public key.
         *
         * @param newKey - new public key in the raw format.
         * @param newKeyCredentials - user's credentials of the new public key.
         * @param oldKeyCredentials - user's credentials of the old public key.
         * @return Updated public key.
         * @throw KeysError - if request to service failed, or service return error code.
         */
        virtual virgil::sdk::keys::model::PublicKey update(const std::vector<unsigned char>& newKey,
                const Credentials& newKeyCredentials, const CredentialsExt& oldKeyCredentials) const = 0;
        /**
         * @brief Delete public key associated with given user's credentials.
         * @param credentials - user's credentials.
         * @throw KeysError - if request to service failed, or service return error code.
         */
        virtual void del(const CredentialsExt& credentials) const = 0;
        /**
         * @brief Deletes public key without HTTP request sign by known private key.
         * @note Should be used when private key is lost.
         * @param publicKeyId - public key UUID.
         * @return action_token and userIds to json.
         * @throw KeysError - if request to service failed, or service return error code.
         */
        virtual std::string del(const std::string& publicKeyId) const = 0;
        /**
         * @brief Confirm Delete Public Key operation.
         * @param publicKeyId - public key UUID.
         * @param actionToken - The action token received on Reset Public Key endpoint invocation.
         * @param confirmationCodes - the list of confirmation codes received on all confirmed UDIDs.
         * @throw KeysError - if request to service failed, or service return error code.
         */
        virtual void confirmDel(const std::string& publicKeyId, const std::string& actionToken,
                const std::vector<std::string>& confirmationCodes) const = 0;
        /**
         * @brief Resets the specified old public key with new value.
         *
         * @param oldPublicKeyId - the old public key identifier.
         * @param newKey - new public key in the raw format.
         * @param newKeyCredentials - user's credentials of the new public key.
         * @return action_token and userIds to json.
         * @throw KeysError - if request to service failed, or service return error code.
         */
        virtual std::string reset(const std::string& oldPublicKeyId, const std::vector<unsigned char>& newKey,
                const Credentials& newKeyCredentials) const = 0;
        /**
         * @brief Confirm Reset Public Key operation.
         *
         * @param oldPublicKeyId - the old public key identifier.
         * @param newKeyCredentials - user's credentials of the new public key.
         * @param actionToken - The action token received on Reset Public Key endpoint invocation.
         * @param confirmationCodes - the list of confirmation codes received on all confirmed UDIDs.
         * @throw KeysError - if request to service failed, or service return error code.
         */
        virtual virgil::sdk::keys::model::PublicKey confirmReset(const std::string& oldPublicKeyId,
                const Credentials& newKeyCredentials, const std::string& actionToken,
                const std::vector<std::string>& confirmationCodes) const = 0;
        /**
         * @brief Search public key associated with a given user identifier.
         * @param userId - user unique identifier: email, phone, fax, application, etc.
         * @return Public keys associated with given user.
         * @throw KeysError - if request to service failed, or service return error code.
         */
        virtual virgil::sdk::keys::model::PublicKey grab(const std::string& userId) const = 0;
        /**
         * @brief Search public key associated with a given user's credentials.
         * @param credentials - user's credentials.
         * @return Public key and user's data associated with given user's credentials.
         * @throw KeysError - if request to service failed, or service return error code.
         */
        virtual virgil::sdk::keys::model::PublicKey grab(const CredentialsExt& credentials) const = 0;
    };
}}}}

#endif /* VIRGIL_SDK_KEYS_PUBLIC_KEY_CLIENT_BASE_H */
