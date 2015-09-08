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

#ifndef VIRGIL_SDK_PRIVATE_KEYS_CLIENT_ENDPOINT_URI_H
#define VIRGIL_SDK_PRIVATE_KEYS_CLIENT_ENDPOINT_URI_H

#include <string>

namespace virgil { namespace sdk { namespace privatekeys { namespace client {
    /**
     * @brief This class provide URIs to the Virgil Private Key endpoints.
     * @note All endpoints start with forward slash symbol "/" and contain version.
     */
    class EndpointUri {
    public:
        enum class Version { V2 };
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
         * @name Authentication management.
         */
        //@{

        std::string updateSession() const;
        //@}

        /**
         * @name Container management.
         */
        //@{
        /**
         * @brief Return endpoint that create container to store future Private Key's instances.
         */
        std::string createContainer() const;
        /**
         * @brief Return endpoint that get Container Object Data with public key id.
         * @param publicKeyId - public key UUID.
         */
        std::string getContainerDetails(const std::string& publicKeyID) const;
        /**
         * @brief Return endpoint that udpdate container information.
         */
        std::string updateContainerInformation() const;
        /**
         * @brief Return endpoint that reset container password.
         */
        std::string resetContainerPassword() const;
        /**
         * @brief Return endpoint that confirm the password reset action.
         */
        std::string confirmToken() const;
        /**
         * @brief Return endpoint that delete container to store future Private Key's instances.
         */
        std::string deleteContainer() const;
        //@}

        /**
         * @name Private Key management.
         */
        //@{
        /**
         * @brief Return endpoint that add private key to the service.
         */
        std::string addPrivateKey() const;
        /**
         * @brief Return endpoint that extract private key by its UUID.
         * @param publicKeyId - public key UUID.
         */
        std::string getPrivateKey(const std::string& publicKeyID) const;
        /**
         * @brief Return endpoint that delete private key.
         */
        std::string deletePrivateKey() const;
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

#endif /* VIRGIL_SDK_PRIVATE_KEYS_CLIENT_ENDPOINT_URI_H */
