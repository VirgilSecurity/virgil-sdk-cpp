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

#ifndef VIRGIL_SDK_GENERATORJWTPROVIDER_H
#define VIRGIL_SDK_GENERATORJWTPROVIDER_H

#include <virgil/sdk/jwt/interfaces/AccessTokenProviderInterface.h>
#include <virgil/sdk/jwt/JwtGenerator.h>

namespace virgil {
    namespace sdk {
        namespace jwt {
            namespace providers {
                /*!
                 * @brief Implementation of AccessTokenProviderInterface which provides generated JWTs
                 */
                class GeneratorJwtProvider : public interfaces::AccessTokenProviderInterface {
                public:
                    /*!
                     * @brief Constructor
                     * @param jwtGenerator JwtGenerator instance for generating new tokens
                     * @param defaultIdentity identity that will be used for generating token
                     * if tokenContext do not have it (e.g. for read operations)
                     * @param additionalData std::unordered_map with additional data, that will be present in token
                     * @warning Do not create cards with defaultIdentity
                     */
                    GeneratorJwtProvider(JwtGenerator jwtGenerator,
                                         std::string defaultIdentity,
                                         std::unordered_map<std::string, std::string> additionalData
                                         = std::unordered_map<std::string, std::string>());

                    /*!
                     * @brief Provides new generated JWT
                     * @param tokenContext TokenContext provides context explaining why token is needed
                     * @return std::future with std::shared_ptr to AccessTokenInterface implementation
                     */
                    std::future<std::shared_ptr<interfaces::AccessTokenInterface>> getToken(const TokenContext& tokenContext);

                    /*!
                     * @brief Getter
                     * @return JwtGenerator instance Provider uses for generating new tokens
                     */
                    const JwtGenerator& jwtGenerator() const;

                    /*!
                     * @brief Getter
                     * @return identity that will be used for generating token
                     * if tokenContext do not have it (e.g. for read operations)
                     */
                    const std::string& defaultIdentity() const;

                    /*!
                     * @brief Getter
                     * @return std::unordered_map with additional data, that added to generated tokens
                     */
                    const std::unordered_map<std::string, std::string>& additionalData() const;

                private:
                    JwtGenerator jwtGenerator_;
                    std::string defaultIdentity_;
                    std::unordered_map<std::string, std::string> additionalData_;
                };
            }
        }
    }
}

#endif //VIRGIL_SDK_GENERATORJWTPROVIDER_H