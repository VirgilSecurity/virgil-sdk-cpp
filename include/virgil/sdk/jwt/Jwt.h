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

#ifndef VIRGIL_SDK_JWT_H
#define VIRGIL_SDK_JWT_H

#include <virgil/sdk/jwt/interfaces/AccessTokenInterface.h>
#include <virgil/sdk/jwt/JwtHeaderContent.h>
#include <virgil/sdk/jwt/JwtBodyContent.h>

namespace virgil {
    namespace sdk {
        namespace jwt {
            /*!
             * @brief Class implementing AccessTokenInterface in terms of Virgil JWT
             */
            class Jwt : public interfaces::AccessTokenInterface {
            public:
                /*!
                 * @brief Constructor
                 * @param headerContent JwtHeaderContent representing header of Jwt
                 * @param bodyContent JwtBodyContent representing body of Jwt
                 * @param signatureContent signature data of Jwt
                 */
                Jwt(JwtHeaderContent headerContent,
                    JwtBodyContent bodyContent,
                    VirgilByteArray signatureContent);

                /*!
                 * @brief Initializes Jwt from its string representation
                 * @param stringRepresentation must be equal to
                 * base64UrlEncode(JWT Header) + "." + base64UrlEncode(JWT Body) + "." + base64UrlEncode(Jwt Signature)
                 * @return Jwt instance
                 */
                static Jwt parse(const std::string& stringRepresentation);

                /*!
                 * @brief Getter
                 * @return JwtHeaderContent representing header of Jwt
                 */
                const JwtHeaderContent& headerContent() const;

                /*!
                 * @brief Getter
                 * @return JwtBodyContent representing body of Jwt
                 */
                const JwtBodyContent& bodyContent() const;

                /*!
                 * @brief Getter
                 * @return signature data of Jwt
                 */
                const VirgilByteArray& signatureContent() const;

                /*!
                 * @brief Provides string representation of token
                 * @return string representation of token
                 */
                const std::string& stringRepresentation() const;

                /*!
                 * @brief Extracts identity
                 * @return std::string with identity
                 */
                const std::string& identity() const;

                /*!
                 * @brief Returns JWT data that should be signed
                 * @return JWT data that should be signed
                 */
                const VirgilByteArray& dataToSign() const;

                /*!
                 * @brief Returns whether or not token is expired
                 * @return true if token is expired, false otherwise
                 */
                bool isExpired() const;

                /*!
                 * @brief Returns JWT data that should be signed
                 * @param headerContent JwtHeaderContent representing header of Jwt
                 * @param bodyContent JwtBodyContent representing body of Jwt
                 * @return JWT data that should be signed
                 */
                static VirgilByteArray dataToSign(const JwtHeaderContent& headerContent,
                                                  const JwtBodyContent& bodyContent);

            private:
                JwtHeaderContent headerContent_;
                JwtBodyContent bodyContent_;
                VirgilByteArray signatureContent_;
                std::string stringRepresentation_;
                VirgilByteArray dataToSign_;

                const std::string signatureBase64Url() const;
            };
        }
    }
}

#endif //VIRGIL_SDK_JWT_H