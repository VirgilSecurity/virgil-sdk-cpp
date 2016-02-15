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

#ifndef VIRGIL_SDK_MODEL_VIRGIL_CARD_IDENTITY_H
#define VIRGIL_SDK_MODEL_VIRGIL_CARD_IDENTITY_H

#include <string>

#include <virgil/sdk/model/Identity.h>

namespace virgil {
namespace sdk {
    namespace model {
        /**
         * @brief
         */
        class IdentityExtended {
        public:
            IdentityExtended() = default;
            IdentityExtended(const bool confirme, const std::string& id, const std::string& createdAt,
                             const Identity& identity);

            bool getConfirme() const;
            const std::string& getId() const;
            const std::string& getCreatedAt() const;
            const Identity& getIdentity() const;

        private:
            bool confirme_ = false;
            std::string id_;
            std::string createdAt_;
            Identity identity_;
        };

        inline bool operator==(const IdentityExtended& left, const IdentityExtended& right) {
            if (left.getConfirme() == right.getConfirme() && left.getId() == right.getId() &&
                left.getCreatedAt() == right.getCreatedAt() && left.getIdentity() == right.getIdentity()) {
                return 1;
            }

            return 0;
        }

        inline bool operator!=(const IdentityExtended& left, const IdentityExtended& right) {
            return !(left == right);
        }
    }
}
}

#endif /* VIRGIL_SDK_MODEL_VIRGIL_CARD_IDENTITY_H */
