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

#ifndef VIRGIL_SDK_KEYS_PUBLIC_KEY_CLIENT_H
#define VIRGIL_SDK_KEYS_PUBLIC_KEY_CLIENT_H

#include <memory>

#include <virgil/sdk/keys/client/PublicKeyClientBase.h>
#include <virgil/sdk/keys/client/KeysClientConnection.h>

namespace virgil { namespace sdk { namespace keys { namespace client {
    /**
     * @brief Default implenetation of class PublicKeyClientBase.
     */
    class PublicKeyClient final : public PublicKeyClientBase {
    public:
        /**
         * @brief Initialize client with HTTP layer connection.
         */
        explicit PublicKeyClient(const std::shared_ptr<KeysClientConnection>& connection);
        /**
         * @name Base class implementation
         */
        //@{
        virgil::sdk::keys::model::PublicKey add(const std::vector<unsigned char>& key,
                const std::vector<virgil::sdk::keys::model::UserData>& userData,
                const Credentials& credentials, const std::string& uuid) const override;
        virgil::sdk::keys::model::PublicKey get(const std::string& publicKeyId) const override;
        virgil::sdk::keys::model::PublicKey update(const std::vector<unsigned char>& newKey,
                const Credentials& newKeyCredentials, const Credentials& oldKeyCredentials,
                const std::string& uuid) const override;
        void del(const Credentials& credentials, const std::string& uuid) const override;
        virgil::sdk::keys::model::PublicKey grab(const std::string& userId) const override;
        virgil::sdk::keys::model::PublicKey grab(const Credentials& credentials,
                const std::string& uuid) const override;
        //@}
    private:
        std::shared_ptr<KeysClientConnection> connection_;
    };
}}}}

#endif /* VIRGIL_SDK_KEYS_PUBLIC_KEY_CLIENT_H */
