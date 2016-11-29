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

#ifndef VIRGIL_SDK_HTTP_RESPONSE_H
#define VIRGIL_SDK_HTTP_RESPONSE_H

#include <string>
#include <map>

namespace virgil {
namespace sdk {
    namespace http {
        /**
         * @brief This is base class for all HTTP responses.
         */
        class Response {
        public:
            /**
             * @brief HTTP response codes.
             */
            enum class StatusCode {
                OK = 200,
                REQUEST_ERROR = 400,
                AUTHORIZATION_ERROR = 401,
                FORBIDDEN = 403,
                ENTITY_NOT_FOUND = 404,
                METHOD_NOT_ALLOWED = 405,
                SERVER_ERROR = 500
            };
            /**
             * @name Types aliases
             */
            //@{
            using Header = std::map<std::string, std::string>;
            using Parameters = std::map<std::string, std::string>;
            //@}
            /**
             * @name Accessors
             */
            //@{
            /**
             * @brief Set response body.
             */
            Response& body(const std::string& body);
            /**
             * @brief Return response body.
             */
            std::string body() const;
            /**
             * @brief Set response content type.
             */
            Response& contentType(const std::string& contentType);
            /**
             * @brief Return response content type.
             */
            std::string contentType() const;
            /**
             * @brief Set response header.
             */
            Response& header(const Header& header);
            /**
             * @brief Get response header.
             */
            Header header() const;
            /**
             * @brief Set response status code.
             */
            Response& statusCode(StatusCode statusCode);
            /**
             * @brief Return response status code.
             */
            StatusCode statusCode() const;
            /**
             * @brief Set response status code from integer value.
             * @throw std::logic_error - if given code is not found in @link Response::StatusCode @endlink enum.
             */
            Response& statusCodeRaw(int code);
            /**
             * @brief Return response status code integer value.
             */
            int statusCodeRaw() const;
            //@}
            /**
             * @brief Return true if response contains error status code.
             */
            bool fail() const;

        private:
            std::string body_;
            std::string contentType_;
            Header header_;
            StatusCode statusCode_ = StatusCode::REQUEST_ERROR;
        };
    }
}
}

#endif /* VIRGIL_SDK_HTTP_RESPONSE_H */
