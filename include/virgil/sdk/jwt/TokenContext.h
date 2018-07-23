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

#ifndef VIRGIL_SDK_TOKENCONTEXT_H
#define VIRGIL_SDK_TOKENCONTEXT_H

#include <string>
#include <memory>

namespace virgil {
    namespace sdk {
        namespace jwt {
            /*!
             * @brief Class used to provide additional info for AccessTokenProviderInterface implementations and explain why token is needed
             */
            class TokenContext {
            public:
                /*!
                 * @brief Constructor
                 * @param operation std::string with operation for which token is needed.
                 * CardManager uses following operations:
                 *    - "get"
                 *    - "search"
                 *    - "publish"
                 * @param identity std::string with identity to use in token
                 * @param forceReload if true AccessTokenProviderInterface implementation should reset cached token, if such exist
                 */
                TokenContext(std::string operation,
                             std::string identity = std::string(),
                             bool forceReload = false);

                /*!
                 * @brief Getter
                 * @return std::string with operation for which token is needed
                 * @note CardManager uses following operations:
                 *   - "get"
                 *   - "search"
                 *   - "publish"
                 */
                const std::string& operation() const;

                /*!
                 * @brief Getter
                 * @return std::string with identity to use in token
                 */
                const std::string& identity() const;

                /*!
                 * @brief Getter
                 * @return if true AccessTokenProviderInterface implementation should reset cached token, if such exist
                 */
                bool forceReload() const;

            private:
                std::string identity_;
                std::string operation_;
                bool forceReload_;
            };
        }
    }
}

#endif //VIRGIL_SDK_TOKENCONTEXT_H