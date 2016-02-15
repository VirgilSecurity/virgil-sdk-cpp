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

#ifndef VIRGIL_SDK_HTTP_REQUEST_H
#define VIRGIL_SDK_HTTP_REQUEST_H

#include <string>
#include <map>

#include <virgil/sdk/Credentials.h>

namespace virgil {
namespace sdk {
    namespace http {
        /**
         * @brief This is base class for all HTTP requests.
         */
        class Request {
        public:
            /**
             * @name Types aliases
             */
            //@{
            using Header = std::map<std::string, std::string>;
            using Parameters = std::map<std::string, std::string>;
            //@}
            /**
             * @name Inner types
             */
            //@{
            enum class Method { GET, POST, PUT, DEL };
            //@}
            /**
             * @name Accessors
             */
            //@{
            /**
             * @brief Set base address URI.
             */
            Request& baseAddress(const std::string& baseAddress);
            /**
             * @brief Return base address URI.
             */
            std::string baseAddress() const;
            /**
             * @brief Set request body.
             */
            Request& body(const std::string& body);
            /**
             * @brief Return request body.
             */
            std::string body() const;
            /**
             * @brief Set request content type.
             */
            Request& contentType(const std::string& contentType);
            /**
             * @brief Return request content type.
             */
            std::string contentType() const;
            /**
             * @brief Set request endpoint.
             */
            Request& endpoint(const std::string& endpoint);
            /**
             * @brief Return request endpoint.
             */
            std::string endpoint() const;
            /**
             * @brief Set request header.
             */
            Request& header(const Header& header);
            /**
             * @brief Get request header.
             */
            Header header() const;
            /**
             * @brief Set request parameters.
             */
            Request& parameters(const Parameters& parameters);
            /**
             * @brief Get request parameters.
             */
            Parameters parameters() const;
            /**
             * @brief Return request URI.
             */
            std::string uri() const;
            /**
             * @brief Set request HTTP method.
             */
            Request& method(const Method& method);
            /**
             * @brief Get request HTTP method.
             */
            Method method() const;
            /**
             * @brief Short form of method Request::method(Method::GET)
             */
            Request& get();
            /**
             * @brief Short form of method Request::method(Method::POST)
             */
            Request& post();
            /**
             * @brief Short form of method Request::method(Method::PUT)
             */
            Request& put();
            /**
             * @brief Short form of method Request::method(Method::DELETE)
             */
            Request& del();
            //@}
        private:
            std::string baseAddress_;
            std::string body_;
            std::string contentType_;
            std::string endPoint_;
            Header header_;
            Parameters parameters_;
            Method method_;
        };

        Request signRequest(const std::string& virgilCardId, const virgil::sdk::Credentials& credentials,
                            const virgil::sdk::http::Request& request);

        Request signRequest(const virgil::sdk::Credentials& credentials, const virgil::sdk::http::Request& request);
    }
}
}

#endif /* VIRGIL_SDK_HTTP_REQUEST_H */
