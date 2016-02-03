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

#ifndef VIRGIL_SDK_PUBLIC_ENDPOINT_URI_H
#define VIRGIL_SDK_PUBLIC_ENDPOINT_URI_H

#include <string>

namespace virgil { namespace sdk { namespace endpoints {
    /**
     * @brief This class provide URIs to the Virgil Public Key endpoints.
     * @note All endpoints start with forward slash symbol "/" and contain version.
     */
    class PublicKeysEndpointUri {
    public:
        //@}
        /**
         * @name Public Key management.
         */
        //@{
        /**
         * @brief Returns the endpoint in charge of a public key by its UUID extraction.
         * @param publicKeyId - public key UUID.
         */
        static std::string publicKeyGet(const std::string& publicKeyId);
        /**
         * @brief Returns the endpoint in charge of the Public Key revoke.
         * @param publicKeyId - public key UUID.
         */
        static std::string publicKeyRevoke(const std::string& publicKeyId);
        //@}
        /**
         * @name Virgil Card management.
         */
        //@{
        /**
         * @brief Returns the endpoint in charge of a Virgil Card creation.
         */
        static std::string virgilCardCreate();
        /**
         * @brief Returns the endpoint in charge of the Virgil Card searches by provided parameters.
         */
        static std::string virgilCardSearch();
        /**
         * @brief Returns the endpoint in charge of the Virgil Cards searches by a defined pattern.
         */
        static std::string virgilCardSearchApp();
        /**
         * @brief Returns the endpoint in charge of the Virgil Card trust.
         * @param virgilCardId - Virgil Card Id.
         */
        static std::string virgilCardTrust(const std::string& virgilCardId);
        /**
         * @brief Returns the endpoint in charge of the Virgil Card untrust.
         * @param virgilCardId - Virgil Card Id.
         */
        static std::string virgilCardUntrust(const std::string& virgilCardId);
        /**
         * @brief Returns the endpoint in charge of the Virgil Card revoke.
         * @param virgilCardId - Virgil Card Id.
         */
        static std::string virgilCardRevoke(const std::string& virgilCardId);
        //@}
    };
}}}

#endif /* VIRGIL_SDK_PUBLIC_ENDPOINT_URI_H */
