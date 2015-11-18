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

#ifndef VIRGIL_SDK_PRIVATE_KEYS_CONTAINER_ENDPOINT_H
#define VIRGIL_SDK_PRIVATE_KEYS_CONTAINER_ENDPOINT_H

#include <memory>

#include <virgil/sdk/privatekeys/client/ContainerEndpointBase.h>
#include <virgil/sdk/privatekeys/client/CredentialsExt.h>
#include <virgil/sdk/privatekeys/client/KeysClientConnection.h>

namespace virgil { namespace sdk { namespace privatekeys { namespace client {
    /**
    * @brief Default implenetation of class ContainerEndpointBase.
    */
    class ContainerEndpoint final : public ContainerEndpointBase {
    public:
        /**
         * @brief Initialize with HTTP layer connection.
         * @param connection - HTTP layer connection.
         * @throw std::logic_error - if connection is invalid.
         */
        explicit ContainerEndpoint(const std::shared_ptr<KeysClientConnection>& connection);

        /**
         * @name Default class implementation.
         */
        //@{
        void create(const CredentialsExt& credentials,
                const virgil::sdk::privatekeys::model::ContainerType& containerType,
                const std::string& containerPassword) const override;
        virgil::sdk::privatekeys::model::ContainerType getDetails(const std::string& publicKeyId) const override;
        void update(const CredentialsExt& credentials,
                const virgil::sdk::privatekeys::model::ContainerType& containerType,
                const std::string& containerPassword) const override;
        void resetPassword(const virgil::sdk::privatekeys::model::UserData& userData,
                const std::string& newContainerPassword) const override;
        void confirm(const std::string& confirmToken) const override;
        void del(const CredentialsExt& credentials) const override;
        //@}
    private:
        std::shared_ptr<KeysClientConnection> connection_;
    };
}}}}

#endif /* VIRGIL_SDK_PRIVATE_KEYS_CONTAINER_ENDPOINT_H */
