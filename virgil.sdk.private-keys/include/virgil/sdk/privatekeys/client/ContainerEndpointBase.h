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

#ifndef VIRGIL_SDK_PRIVATE_KEYS_CONTAINER_ENDPOINT_BASE_H
#define VIRGIL_SDK_PRIVATE_KEYS_CONTAINER_ENDPOINT_BASE_H

#include <string>

#include <virgil/sdk/privatekeys/client/Credentials.h>
#include <virgil/sdk/privatekeys/model/ContainerType.h>
#include <virgil/sdk/privatekeys/model/UserData.h>

namespace virgil { namespace sdk { namespace privatekeys { namespace client {
    /**
    * @brief Endpoint "/container" of the Virgil Private Keys Service API.
    */
    class ContainerEndpointBase {
    public:
        /**
         * @brief Create a new container object to store future Private Key's instances.
         *
         * @param credentials - user's credentials.
         * @param containerType - the type of private keys container.
         * @param containerPassword - represents container password.
         * @throw KeysError - if request to service failed, or service return error code.
         */
        virtual void create(const Credentials& credentials,
                const virgil::sdk::privatekeys::model::ContainerType& containerType,
                const std::string& containerPassword) const = 0;
        /**
         * @brief Get Container Object Data with public key id.
         *
         * @param publicKeyId - public key UUID.
         * @return Container type.
         * @throw KeysError - if request to service failed, or service return error code.
         *
         * @note Require authentication.
         * @see PrivateKeysClient::authenticate()
         */
        virtual virgil::sdk::privatekeys::model::ContainerType getDetails(const std::string& publicKeyId) const = 0;
        /**
         * @brief Update information of existing Container.
         *
         * By invoking this method you can change the Container's Type or/and Container's Password.
         *
         * @param credentials - user's credentials.
         * @param containerType - the type of private keys container.
         * @param containerPassword - represents container password.
         * @throw KeysError - if request to service failed, or service return error code.
         *
         * @note Require authentication.
         * @see PrivateKeysClient::authenticate()
         */
        virtual void update(const Credentials& credentials,
                const virgil::sdk::privatekeys::model::ContainerType& containerType,
                const std::string& containerPassword) const = 0;
        /**
         * @brief Reset the Container Password.
         *
         * @param userData - added user data.
         * @param newContainerPassword - represents new container password.
         * @throw KeysError - if request to service failed, or service return error code.
         *
         * @note A user can reset their Private Key password if the Container Type equals 'easy'.
         *       If the Container Type equals 'normal', the Private Key will be stored in its original form.
         * @see confirm()
         */
        virtual void resetPassword(const virgil::sdk::privatekeys::model::UserData& userData,
                const std::string& newContainerPassword) const = 0;
        /**
         * @brief Confirm password token.
         *
         * @param confirmToken - confirm the password token.
         * @throw KeysError - if request to service failed, or service return error code.
         *
         * @note The token generated during the container reset password invocation only lives for 60 minutes.
         * @see resetPassword()
         */
        virtual void confirm(const std::string& confirmToken) const = 0;
        /**
         * @brief Delete Container Object. Delete existing container object from the Private Key service.
         *
         * @param credentials - user's credentials.
         * @throw KeysError - if request to service failed, or service return error code.
         *
         * @note Require authentication.
         * @see PrivateKeysClient::authenticate()
         */
        virtual void del(const Credentials& credentials) const = 0;
    };
}}}}

#endif /* VIRGIL_SDK_PRIVATE_KEYS_CONTAINER_ENDPOINT_BASE_H */
