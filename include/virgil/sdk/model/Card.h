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

#ifndef VIRGIL_SDK_MODEL_CARD_H
#define VIRGIL_SDK_MODEL_CARD_H

#include <string>
#include <map>

#include <virgil/sdk/model/PublicKey.h>
#include <virgil/sdk/model/CardIdentity.h>

namespace virgil {
namespace sdk {
    namespace model {
        /**
         * @brief Data object represent "Virgil Card" entity.
         */
        class Card {
        public:
            Card() = default;
            Card(const bool confirmed, const std::string& id, const std::string& createdAt, const std::string& hash,
                 const virgil::sdk::model::CardIdentity& cardIdentity, const std::map<std::string, std::string>& data,
                 const virgil::sdk::model::PublicKey& publicKey);

            bool isConfirmed() const;
            const std::string& getId() const;
            const std::string& getCreatedAt() const;
            const std::string& getHash() const;
            const virgil::sdk::model::CardIdentity& getCardIdentity() const;
            const std::map<std::string, std::string>& getData() const;
            const virgil::sdk::model::PublicKey& getPublicKey() const;

        private:
            bool confirmed_ = false;
            std::string id_;
            std::string createdAt_;
            std::string hash_;
            virgil::sdk::model::CardIdentity cardIdentity_;
            std::map<std::string, std::string> data_;
            virgil::sdk::model::PublicKey publicKey_;
        };

        inline bool operator==(const Card& left, const Card& right) {
            if (left.isConfirmed() == right.isConfirmed() && left.getId() == right.getId() &&
                left.getCreatedAt() == right.getCreatedAt() && left.getHash() == right.getHash() &&
                left.getCardIdentity() == right.getCardIdentity() && left.getData() == right.getData() &&
                left.getPublicKey() == right.getPublicKey()) {
                return 1;
            }

            return 0;
        }

        inline bool operator!=(const Card& left, const Card& right) {
            return !(left == right);
        }
    }
}
}

#endif /* VIRGIL_SDK_MODEL_CARD_H */
