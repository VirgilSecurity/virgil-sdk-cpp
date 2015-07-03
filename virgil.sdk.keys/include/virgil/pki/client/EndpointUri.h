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

#ifndef VIRGIL_PKI_CLEINT_ENDPOINT_URI_H
#define VIRGIL_PKI_CLEINT_ENDPOINT_URI_H

#include <string>

namespace virgil { namespace pki { namespace client {
    /**
     * @brief This class provide URIs to the Virgil Public Key endpoints.
     * @note All endpoints start with forward slash symbol "/" and DO NOT contain version.
     */
    class EndpointUri {
    public:
        /**
         * @name Public Key management.
         */
        //@{
        /**
         * @brief Return endpoint that add public key to the account.
         * @note This endpoint can be used for two purposes,
         *     first, add public key to the existing account,
         *     second, add public key to the new account.
         */
        static std::string publicKeyAdd();
        /**
         * @brief Return endpoint that extract public key by its id.
         * @param publicKeyId - public key GUID.
         */
        static std::string publicKeyGet(const std::string& publicKeyId);
        /**
         * @brief Return endpoint that extract all public keys associated with user identifier.
         */
        static std::string publicKeySearch();
        //@}
        /**
         * @name User Data management.
         */
        //@{
        /**
         * @brief Return endpoint that add user data to existing public key.
         */
        static std::string userDataAdd();
        /**
         * @brief Return endpoint that get user data by its GUID.
         */
        static std::string userDataGet(const std::string& userDataId);
        /**
         * @brief Return endpoint that confirm given user data.
         * @param userDataId - user data GUID.
         */
        static std::string userDataConfirm(const std::string& userDataId);
        /**
         * @brief Return endpoint that resend confirmation code for the given user data.
         * @param userDataId - user data GUID.
         */
        static std::string userDataResendConfirm(const std::string& userDataId);
        /**
         * @brief Return endpoint that extract all user data associated with given user identifier.
         */
        static std::string userDataSearch();
        //@}
    private:
        EndpointUri();
    };
}}}

#endif /* VIRGIL_PKI_CLEINT_ENDPOINT_URI_H */
