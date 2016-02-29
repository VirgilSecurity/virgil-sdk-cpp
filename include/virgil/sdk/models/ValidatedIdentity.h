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

#ifndef VIRGIL_SDK_MODEL_IDENTITY_TOKEN_H
#define VIRGIL_SDK_MODEL_IDENTITY_TOKEN_H

#include <string>

#include <virgil/sdk/models/Identity.h>

namespace virgil {
namespace sdk {
    namespace models {
        /**
         * @brief This class represents validated identity
         *
         * @details Validated identity tells that user validate identity and receive related token
         */
        class ValidatedIdentity : public Identity {
        public:
            /**
             * @brief Create empty non valid identity
             */
            ValidatedIdentity() = default;
            /**
             * @brief Create identity with valid token
             *
             * @param token - validation token
             * @param value - identity value, i.e. support@virgilsecurity.com
             * @param type - identity type, i.e. IdentityType::Email
             */
            ValidatedIdentity(const std::string& token, const std::string& value, const IdentityType& type);
            /**
             * @brief Return token that validate underlying identity
             */
            const std::string getToken() const;

        private:
            std::string token_;
        };

        /**
         * @brief Compare identities for equality
         *
         * @return true if given objects are equal, false - otherwise
         */
        inline bool operator==(const ValidatedIdentity& left, const ValidatedIdentity& right) {
            return static_cast<const Identity&>(left) == static_cast<const Identity&>(right) &&
                   left.getToken() == right.getToken();
        }

        /**
         * @brief Compare identities for inequality
         *
         * @return true if given objects are inequal, false - otherwise
         */
        inline bool operator!=(const ValidatedIdentity& left, const ValidatedIdentity& right) {
            return !(left == right);
        }
    }
}
}

#endif /* VIRGIL_SDK_MODEL_IDENTITY_TOKEN_H */
