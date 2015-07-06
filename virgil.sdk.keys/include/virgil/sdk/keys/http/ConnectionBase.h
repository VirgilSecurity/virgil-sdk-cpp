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

#ifndef VIRGIL_SDK_KEYS_HTTP_CONNECTION_BASE_H
#define VIRGIL_SDK_KEYS_HTTP_CONNECTION_BASE_H

#include <string>

#include <virgil/sdk/keys/http/Request.h>
using virgil::sdk::keys::http::Request;
#include <virgil/sdk/keys/http/Response.h>
using virgil::sdk::keys::http::Response;

#include <virgil/sdk/keys/error/PkiError.h>
using virgil::sdk::keys::error::PkiError;

namespace virgil { namespace sdk { namespace keys { namespace http {
    /**
     * @brief This abstract class unifies access to the HTTP layer.
     */
    class ConnectionBase {
    public:
        /**
         * @brief Default API base address URI, i.e. https://pki.virgilsecurity.com/v1
         */
        static const std::string baseAddressDefault;
        /**
         * @brief Configure connection with base address URI.
         * @param appToken - application specific key that is used for all service communications.
         * @param baseAddress - service base address including API version, i.e. https://pki.virgilsecurity.com/v1
         */
        explicit ConnectionBase(const std::string& appToken, const std::string &baseAddress = baseAddressDefault);
        /**
         * @brief Return application specific key.
         */
        std::string appToken() const;
        /**
         * @brief Return API base address.
         */
        std::string baseAddress() const;
        /**
         * @brief Send synchronous request.
         * @param request - request to be send.
         * @throw std::logic_error - if given parameters are inconsistent.
         * @throw std::runtime_error - if error was occured when send request.
         */
        virtual Response send(const Request& request) = 0;
        /**
         * @brief Check response for errors.
         * @param response - HTTP response to check.
         * @param action - PKI action that created the response.
         * @throw PkiError, if HTTP response contains error description.
         */
        virtual void checkResponseError(const Response& response, PkiError::Action action) = 0;
    private:
        std::string appToken_;
        std::string baseAddress_;
    };
}}}}

#endif /* VIRGIL_SDK_KEYS_HTTP_CONNECTION_BASE_H */

