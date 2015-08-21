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

#ifndef VIRGIL_SDK_KEYS_USER_DATA_CLIENT_BASE_H
#define VIRGIL_SDK_KEYS_USER_DATA_CLIENT_BASE_H

#include <string>
#include <vector>

#include <virgil/sdk/keys/model/UserData.h>
#include <virgil/sdk/keys/client/Credentials.h>

namespace virgil { namespace sdk { namespace keys { namespace client {
    /**
     * @brief Endpoint "/user-data" to the Virgil Public Keys Service (API).
     */
    class UserDataClientBase {
    public:
        /**
         * @brief Add user data to the public key.
         *
         * @param userData - added user data.
         * @param credentials - user's credentials.
         * @param uuid - transaction UUID.
         * @return Added user data with UUIDs.
         */
        virtual virgil::sdk::keys::model::UserData add(const virgil::sdk::keys::model::UserData& userData,
                const virgil::sdk::keys::client::Credentials& credentials, const std::string& uuid) const = 0;
        /**
         * @brief Delete specific user data.
         * @param userDataId - user data UUID.
         * @param credentials - user's credentials.
         * @param uuid - transaction UUID.
         */
        virtual void del(const std::string& userDataId,
                const virgil::sdk::keys::client::Credentials& credentials, const std::string& uuid) const = 0;
        /**
         * @brief Confirm user data.
         * @param userDataId - user data UUID.
         * @param code - confirmation code.
         * @param uuid - transaction UUID.
         */
        virtual void confirm(const std::string& userDataId, const std::string& code) const = 0;
        /**
         * @brief Resend user data confirmation code.
         * @param userDataId - user data UUID.
         * @param credentials - user's credentials.
         * @param uuid - transaction UUID.
         */
        virtual void resendConfirmation(const std::string& userDataId,
                const virgil::sdk::keys::client::Credentials& credentials, const std::string& uuid) const = 0;
    };
}}}}

#endif /* VIRGIL_SDK_KEYS_USER_DATA_CLIENT_BASE_H */
