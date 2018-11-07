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

#ifndef VIRGIL_SDK_CACHINGJWTPROVIDER_H
#define VIRGIL_SDK_CACHINGJWTPROVIDER_H

#include <functional>
#include <virgil/sdk/jwt/interfaces/AccessTokenProviderInterface.h>
#include <virgil/sdk/jwt/Jwt.h>

namespace virgil {
    namespace sdk {
        namespace jwt {
            namespace providers {
                /*!
                 * @brief Implementation of AccessTokenProvider which provides AccessToken using cache+renew callback
                 */
                class CachingJwtProvider : public interfaces::AccessTokenProviderInterface {
                public:
                    /*!
                     * @brief Constructor
                     * @param renewJwtCallback std::function, which takes a TokenContext returns std::future with Jwt std::string
                     */
                    CachingJwtProvider(std::function<std::future<std::string>(const TokenContext&)> renewJwtCallback);

                    /*!
                     * @brief Provides access token using callback or cached token
                     * @param tokenContext TokenContext provides context explaining why token is needed
                     * @return std::future with std::shared_ptr to Jwt
                     */
                    std::future<std::shared_ptr<interfaces::AccessTokenInterface>> getToken(const TokenContext& tokenContext);

                    /*!
                     * @brief Getter
                     * @return callback provider uses to obtain token
                     */
                    const std::function<std::future<std::string>(const TokenContext&)>& renewJwtCallback() const;

                    /*!
                     * @brief Getter
                     * @return cached Jwt
                     */
                    const std::shared_ptr<Jwt>& jwt() const;

                private:
                    std::shared_ptr<Jwt> jwt_;
                    std::function<std::future<std::string>(const TokenContext&)> renewJwtCallback_;
                };
            }
        }
    }
}

#endif //VIRGIL_SDK_CACHINGJWTPROVIDER_H