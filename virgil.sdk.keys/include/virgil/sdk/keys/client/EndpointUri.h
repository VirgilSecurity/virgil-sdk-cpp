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

#ifndef VIRGIL_SDK_KEYS_CLEINT_ENDPOINT_URI_H
#define VIRGIL_SDK_KEYS_CLEINT_ENDPOINT_URI_H

#include <string>

namespace virgil { namespace sdk { namespace keys { namespace client {
    /**
     * @brief This class provide URIs to the Virgil Public Key endpoints.
     * @note All endpoints start with forward slash symbol "/" and contain version.
     */
    class EndpointUri {
    public:
        /**
         * @brief Enumerate supported API versions.
         */
        enum class Version {
            V2 /*!< Virgil Public Key Service API version 2 */
        };
    public:
        /**
         * @name Configuration
         */
        //@{
        /**
         * @brief Configure endpoint's URI with version.
         */
        explicit EndpointUri(EndpointUri::Version uriVersion);
        /**
         * @brief Creates endpoints of version 2.
         */
        static EndpointUri v2();
        /**
         * @brief Return endpoint's URI version.
         */
        Version version() const;
        //@}
        /**
         * @name Public Key management.
         */
        //@{
        /**
         * @brief Return endpoint that add public key to the service.
         */
        std::string publicKeyAdd() const;
        /**
         * @brief Return endpoint that extract public key by its UUID.
         * @param publicKeyId - public key UUID.
         */
        std::string publicKeyGet(const std::string& publicKeyId) const;
        /**
         * @brief Return endpoint that udpdate public key by its UUID.
         * @param publicKeyId - public key UUID.
         */
        std::string publicKeyUpdate(const std::string& publicKeyId) const;
        /**
         * @brief Return endpoint that delete public key by its UUID.
         * @param publicKeyId - public key UUID.
         */
        std::string publicKeyDelete(const std::string& publicKeyId) const;
        /**
         * @brief Return endpoint that extract public key associated with user identifier.
         */
        std::string publicKeyGrab() const;
        //@}
        /**
         * @name User Data management.
         */
        //@{
        /**
         * @brief Return endpoint that add user data to existing public key.
         */
        std::string userDataAdd() const;
        /**
         * @brief Return endpoint that delete user data by its UUID.
         */
        std::string userDataDelete(const std::string& userDataId) const;
        /**
         * @brief Return endpoint that confirm given user data.
         * @param userDataId - user data UUID.
         */
        std::string userDataConfirm(const std::string& userDataId) const;
        /**
         * @brief Return endpoint that resend confirmation code for the given user data.
         * @param userDataId - user data UUID.
         */
        std::string userDataResendConfirmation(const std::string& userDataId) const;
        //@}
    private:
        /**
         * @brief Add version to the URI.
         * @return URI with version.
         */
        std::string addVersion(const std::string& uri) const;
    private:
        Version version_;
    };
}}}}

#endif /* VIRGIL_SDK_KEYS_CLEINT_ENDPOINT_URI_H */
