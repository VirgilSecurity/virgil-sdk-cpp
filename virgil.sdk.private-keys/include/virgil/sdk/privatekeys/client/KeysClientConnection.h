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

#ifndef VIRGIL_SDK_PRIVATE_KEYS_HTTP_CONNECTION_BASE_H
#define VIRGIL_SDK_PRIVATE_KEYS_HTTP_CONNECTION_BASE_H

#include <string>

#include <virgil/sdk/privatekeys/client/CredentialsExt.h>
#include <virgil/sdk/privatekeys/error/KeysError.h>
#include <virgil/sdk/privatekeys/http/Connection.h>
#include <virgil/sdk/privatekeys/model/UserData.h>


namespace virgil { namespace sdk { namespace privatekeys { namespace client {
    /**
     * @brief Specific HTTP layer for Virgil Public Keys service.
     */
    class KeysClientConnection : public virgil::sdk::privatekeys::http::Connection {
    public:
        /**
         * @brief Configure connection application specific token and with base address URI.
         * @param appToken - application specific token.
         * @param baseAddress - service API base address.
         */
        KeysClientConnection(const std::string& appToken, const std::string& baseAddress);
        /**
         * @brief Return application specific key.
         */
        std::string appToken() const;
        /**
         * @brief Return service API base address.
         */
        std::string baseAddress() const;
        /**
         * @brief Update authentication token for current session.
         * @param authToken - authentication token.
         */
        void updateSession(const std::string& authToken);
        /**
         * @brief Get an authentication token.
         *
         * @return an authentication token.
         */
        std::string getAuthToken() const;
        /**
         * @brief Send synchronous request.
         * @param request - request to be send.
         * @throw std::logic_error - if given parameters are inconsistent.
         * @throw std::runtime_error - if error was occured when send request.
         */
        virtual virgil::sdk::privatekeys::http::Response send(
                const virgil::sdk::privatekeys::http::Request& request) override;
        /**
         * @brief Send synchronous request.
         * @param request - request to be send.
         * @param credentials - credentials for operations that need user's verification.
         * @throw std::logic_error - if given parameters are inconsistent or invalid.
         * @throw std::runtime_error - if error was occured when send request.
         */
        virtual virgil::sdk::privatekeys::http::Response send(
                const virgil::sdk::privatekeys::http::Request& request, const CredentialsExt& credentials);
        /**
         * @brief Check response for errors.
         * @param response - HTTP response to check.
         * @param action - service action that create given response.
         * @throw KeysError - if HTTP response contains error description.
         */
        virtual void checkResponseError(const virgil::sdk::privatekeys::http::Response& response,
                virgil::sdk::privatekeys::error::KeysError::Action action);
    private:
        std::string appToken_;
        std::string authToken_;
        std::string baseAddress_;
    };
}}}}

#endif /* VIRGIL_SDK_PRIVATE_KEYS_HTTP_CONNECTION_BASE_H */

