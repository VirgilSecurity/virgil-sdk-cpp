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

#ifndef VIRGIL_SDK_MODEL_CARD_SIGN_H
#define VIRGIL_SDK_MODEL_CARD_SIGN_H

#include <string>

namespace virgil {
namespace sdk {
    namespace model {
        /**
         * @brief This class contains detailed information about Signed Card
         */
        class CardSign {
        public:
            /**
             * @brief Create empty non valid object
             */
            CardSign() = default;
            /**
             * @brief Create Card Sign with all related information
             *
             * @param id - Virgil Card Sign identifier
             * @param createdAt - creation timestamp
             * @param signerCardId - identifier of the Virgil Card that was used to sign
             * @param signedCardId - identifier of the Virgil Card that was signed
             * @param signedDigest - signed digest that can be verified within crypto algorithm
             */
            CardSign(const std::string& id, const std::string& createdAt, const std::string& signerCardId,
                     const std::string& signedCardId, const std::string& signedDigest);
            /**
             * @brief Return Virgil Card Sign identifier
             */
            const std::string& getId() const;
            /**
             * @brief Return creation timestamp
             */
            const std::string& getCreatedAt() const;
            /**
             * @brief Return identifier of the Virgil Card that was used to sign
             */
            const std::string& getSignerCardId() const;
            /**
             * @brief Return identifier of the Virgil Card that was signed
             */
            const std::string& getSignedCardId() const;
            /**
             * @brief Return signed digest that can be verified within crypto algorithm
             */
            const std::string& getSignedDigest() const;

        private:
            std::string id_;
            std::string createdAt_;
            std::string signerCardId_;
            std::string signedCardId_;
            std::string signedDigest_;
        };
        /**
         * @brief Compare Virgil Card's Sign for equality
         *
         * @return true if given objects are equal, false - otherwise
         */
        inline bool operator==(const CardSign& left, const CardSign& right) {
            return left.getId() == right.getId() && left.getCreatedAt() == right.getCreatedAt() &&
                   left.getSignerCardId() == right.getSignerCardId() &&
                   left.getSignedCardId() == right.getSignedCardId() &&
                   left.getSignedDigest() == right.getSignedDigest();
        }
        /**
         * @brief Compare Virgil Card's Sign for inequality
         *
         * @return true if given objects are inequal, false - otherwise
         */
        inline bool operator!=(const CardSign& left, const CardSign& right) {
            return !(left == right);
        }
    }
}
}

#endif /* VIRGIL_SDK_MODEL_CARD_SIGN_H */
