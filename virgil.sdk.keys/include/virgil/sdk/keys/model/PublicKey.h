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

#ifndef VIRGIL_SDK_KEYS_MODEL_PUBLIC_KEY_H
#define VIRGIL_SDK_KEYS_MODEL_PUBLIC_KEY_H

#include <string>
#include <vector>

#include <virgil/sdk/keys/model/UserData.h>
using virgil::sdk::keys::model::UserData;

namespace virgil { namespace sdk { namespace keys { namespace model {
    /**
     * @brief Data object represent "Virgil Public Key" entity.
     */
    class PublicKey {
    public:
        /**
         * @brief Set parent account GUID.
         */
        PublicKey& accountId (const std::string& accountId);
        /**
         * @brief Get parent account GUID.
         */
        std::string accountId () const;
        /**
         * @brief Set public key GUID.
         */
        PublicKey& publicKeyId (const std::string& publicKeyId);
        /**
         * @brief Get public key GUID.
         */
        std::string publicKeyId () const;
        /**
         * @brief Set public key.
         */
        PublicKey& key(const std::vector<unsigned char> key);
        /**
         * @brief Get public key.
         */
        std::vector<unsigned char> key() const;
        /**
         * @brief Return user data associated with public key.
         */
        const std::vector<UserData>& userData() const;
        /**
         * @brief Return user data associated with public key.
         */
        std::vector<UserData>& userData();
    private:
        std::string accountId_;
        std::string publicKeyId_;
        std::vector<unsigned char> key_;
        std::vector<UserData> userData_;
    };
}}}}

#endif /* VIRGIL_SDK_KEYS_MODEL_PUBLIC_KEY_H */