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

#ifndef VIRGIL_SDK_JWTBODYCONTENT_H
#define VIRGIL_SDK_JWTBODYCONTENT_H

#include <string>
#include <ctime>
#include <unordered_map>
#include <virgil/sdk/Common.h>

namespace virgil {
    namespace sdk {
        namespace jwt {
            /*!
             * @brief Class representing JWT Body content
             */
            class JwtBodyContent {
            public:
                /*!
                 * @brief Constructor
                 * @param appId std::string with issuer containing application id. Can be taken <a href="https://dashboard.virgilsecurity.com">here</a>
                 * @param identity std::string with identity (must be equal to RawSignedModel identity when publishing card)
                 * @param expiresAt std::time with expiration date of token
                 * @param issuedAt std::time with issued date of token
                 * @param additionalData std::unordered_map with additional data
                 */
                JwtBodyContent(std::string appId,
                               std::string identity,
                               std::time_t expiresAt,
                               std::time_t issuedAt,
                               std::unordered_map<std::string, std::string> additionalData
                               = std::unordered_map<std::string, std::string>());

                /*!
                 * @brief Initializes JwtBodyContent from a base64Url encoded std::string
                 * @param base64url base64Url encoded std::string with JwtBodyContent
                 * @return JwtBodyContent instance
                 */
                static JwtBodyContent parse(const std::string& base64url);

                /*!
                 * @brief Getter
                 * @return std::string with issuer containing application id
                 * @note Can be taken <a href="https://dashboard.virgilsecurity.com">here</a>
                 */
                const std::string& appId() const;

                /*!
                 * @brief Getter
                 * @return std::string with identity
                 * @note must be equal to RawSignedModel identity when publishing card
                 */
                const std::string& identity() const;

                /*!
                 * @brief Getter
                 * @return std::time with expiration date of token
                 */
                std::time_t expiresAt() const;

                /*!
                 * @brief Getter
                 * @return std::time with issued date of token
                 */
                std::time_t issuedAt() const;

                /*!
                 * @brief Getter
                 * @return std::unordered_map with additional data
                 */
                const std::unordered_map<std::string, std::string>& additionalData() const;

                /*!
                 * @brief Exports JwtBodyContent as base64Url encoded string
                 * @return base64Url encoded string with JwtBodyContent
                 */
                std::string base64Url() const;

            private:
                std::string appId_;
                std::string identity_;
                std::time_t expiresAt_;
                std::time_t issuedAt_;
                std::unordered_map<std::string, std::string> additionalData_;
            };
        }
    }
}

#endif //VIRGIL_SDK_JWTBODYCONTENT_H