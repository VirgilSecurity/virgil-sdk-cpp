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

#ifndef VIRGIL_PKI_CLIENT_USER_DATA_CLIENT_BASE_H
#define VIRGIL_PKI_CLIENT_USER_DATA_CLIENT_BASE_H

#include <virgil/pki/client/UserDataClient.h>

namespace virgil { namespace pki { namespace client {
    /**
     * @brief Base implenetation of class UserDataClient.
     */
    class UserDataClientBase final : public UserDataClient {
    public:
        /**
         * @brief Inherit base class constructor.
         */
        using UserDataClient::UserDataClient;
        /**
         * @name Base class implementation.
         */
        //@{
        UserData add(const std::string& publicKeyId, const std::string& className,
                const std::string& type, const std::string& value) const override;
        UserData get(const std::string& userDataId) const override;
        void confirm(const std::string& userDataId, const std::string& code) const override;
        void resendConfirmation(const std::string& userDataId) const override;
        virtual std::vector<UserData> search(const std::string& userId, bool expandPublicKey = false) const override;
        //@}
    };
}}}

#endif /* VIRGIL_PKI_CLIENT_USER_DATA_CLIENT_BASE_H */
