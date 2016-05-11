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

#ifndef VIRGIL_SDK_MODELS_CARD_MODEL_H
#define VIRGIL_SDK_MODELS_CARD_MODEL_H

#include <string>
#include <map>

#include <virgil/sdk/models/IdentityModel.h>
#include <virgil/sdk/models/PublicKeyModel.h>

namespace virgil {
namespace sdk {
    namespace models {
        /**
         * @brief Data object represent "Virgil Card" entity
         */
        class CardModel {
        public:
            /**
             * @brief Create empty non valid Virgil Card
             */
            CardModel() = default;
            /**
             * @brief Create Virgil Card with all associated data
             *
             * @param id - Virgil Card identifier
             * @param createdAt - creation timestamp
             * @param hash - compressed information about Virgil Card, this value can be used for signing
             * @param cardIdentity - identity associated with Virgil Card
             * @param data - custom data
             * @param publicKey - Public Key connected to the Virgil Card
             * @param authorizedBy - by whom authorized
             */
            CardModel(const std::string& id, const std::string& createdAt, const std::string& hash,
                      const virgil::sdk::models::IdentityModel& cardIdentity,
                      const std::map<std::string, std::string>& data,
                      const virgil::sdk::models::PublicKeyModel& publicKey, const std::string& authorizedBy);
            /**
             * @brief Return Virgil Card identifier
             */
            const std::string getId() const;
            /**
             * @brief Return creation timestamp
             */
            const std::string getCreatedAt() const;
            /**
             * @brief Return compressed information about Virgil Card
             * @note This value can be used for signing
             */
            const std::string getHash() const;
            /**
             * @brief Return identity associated with Virgil Card
             */
            const virgil::sdk::models::IdentityModel getCardIdentity() const;
            /**
             * @brief Return user's custom data associated with Virgil Card
             */
            const std::map<std::string, std::string> getData() const;
            /**
             * @brief Return Public Key connected to the Virgil Card
             */
            const virgil::sdk::models::PublicKeyModel getPublicKey() const;
            /**
             * @brief Return whether Identity connected to the Virgil Card is confirmed by user, or not
             */
            std::string authorizedBy() const;

        private:
            std::string id_;
            std::string createdAt_;
            std::string hash_;
            virgil::sdk::models::IdentityModel cardIdentity_;
            std::map<std::string, std::string> data_;
            virgil::sdk::models::PublicKeyModel publicKey_;
            std::string authorizedBy_;
        };
        /**
         * @brief Compare Virgil Cards for equality
         *
         * @return true if given objects are equal, false - otherwise
         */
        inline bool operator==(const CardModel& left, const CardModel& right) {
            return left.authorizedBy() == right.authorizedBy() && left.getId() == right.getId() &&
                   left.getCreatedAt() == right.getCreatedAt() && left.getHash() == right.getHash() &&
                   left.getCardIdentity() == right.getCardIdentity() && left.getData() == right.getData() &&
                   left.getPublicKey() == right.getPublicKey();
        }
        /**
         * @brief Compare Virgil Cards for inequality
         *
         * @return true if given objects are inequal, false - otherwise
         */
        inline bool operator!=(const CardModel& left, const CardModel& right) {
            return !(left == right);
        }
    }
}
}

#endif /* VIRGIL_SDK_MODELS_CARD_MODEL_H */
