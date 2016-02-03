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

#ifndef VIRGIL_SDK_CLIENT_CONNECTION_H
#define VIRGIL_SDK_CLIENT_CONNECTION_H

#include <string>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/Credentials.h>
#include <virgil/sdk/http/Connection.h>
#include <virgil/sdk/Error.h>
#include <virgil/sdk/model/VirgilCard.h>


namespace virgil { namespace sdk { namespace client {

    /**
     * @brief Specific HTTP layer for Virgil Public Keys service.
     */
    class ClientConnection : public virgil::sdk::http::Connection {
    public:
        /**
         * @brief Configure connection application specific token and with base address URI.
         * @param appToken - application specific token.
         * @param baseAddress - service API base address.
         */
        explicit ClientConnection(const std::string& accessToken);
        /**
         * @brief Return access token.
         */
        std::string accessToken() const;
        /**
         * @brief Send synchronous request.
         * @param request - request to be send.
         * @throw std::logic_error - if given parameters are inconsistent.
         * @throw std::runtime_error - if error was occured when send request.
         */
        virgil::sdk::http::Response send(const virgil::sdk::http::Request& request) override;

        virgil::sdk::http::Request signRequest(const std::string& virgilCardId,
                const virgil::sdk::Credentials& credentials, const virgil::sdk::http::Request& request);

        virgil::sdk::http::Request signRequest(const virgil::sdk::Credentials& credentials,
                const virgil::sdk::http::Request& request);

        std::string signHash(const std::string& hash, const Credentials& credentials);

         std::string encryptJsonBody(const virgil::sdk::model::VirgilCard& privateKeysServiceCard, 
                const std::string& jsonBody);

        /**
         * @brief Check response for errors.
         * @param response - HTTP response to check.
         * @param action - service action that create given response.
         * @throw Error - if HTTP response contains error description.
         */
        virtual void checkResponseError(const virgil::sdk::http::Response& response,
                virgil::sdk::Error::Action action);
    private:

    private:
        std::string accessToken_;
    };
}}}

#endif /* VIRGIL_SDK_CLIENT_CONNECTION_H */

