/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#ifndef VIRGIL_SDK_JWTHEADERCONTENT_H
#define VIRGIL_SDK_JWTHEADERCONTENT_H

#include <string>

namespace virgil {
    namespace sdk {
        namespace jwt {
            /*!
             * @brief Class representing JWT Header content
             */
            class JwtHeaderContent {
            public:
                /*!
                 * @brief Constructor
                 * @param keyIdentifier identifier of public key which should be used to verify signature.
                 * Can be taken <a href="https://dashboard.virgilsecurity.com/api-keys">here</a>
                 * @param algorithm used signature algorithm
                 * @param type token type
                 * @param contentType content type for this JWT
                 */
                JwtHeaderContent(std::string keyIdentifier,
                                 std::string algorithm = "VEDS512",
                                 std::string type = "JWT",
                                 std::string contentType = "virgil-jwt;v=1");

                /*!
                 * @brief Initializes JwtHeaderContent from base64Url encoded string
                 * @param base64url base64Url encoded string with JwtHeaderContent
                 * @return JwtHeaderContent instance
                 */
                static JwtHeaderContent parse(const std::string& base64url);

                /*!
                 * @brief Getter
                 * @return used signature algorithm
                 */
                const std::string& algorithm() const;

                /*!
                 * @brief Getter
                 * @return token type
                 */
                const std::string& type() const;

                /*!
                 * @brief Getter
                 * @return content type for this JWT
                 */
                const std::string& contentType() const;

                /*!
                 * @brief Getter
                 * @return identifier of public key which should be used to verify signature
                 * @note Can be taken <a href="https://dashboard.virgilsecurity.com/api-keys">here</a>
                 */
                const std::string& keyIdentifier() const;

                /*!
                 * @brief Exports JwtHeaderContent as base64Url encoded string
                 * @return base64Url encoded string with JwtHeaderContent
                 */
                std::string base64Url() const;

            private:
                std::string algorithm_;
                std::string type_;
                std::string contentType_;
                std::string keyIdentifier_;
            };
        }
    }
}

#endif //VIRGIL_SDK_JWTHEADERCONTENT_H