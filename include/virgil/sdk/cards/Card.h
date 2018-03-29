/**
 * Copyright (C) 2018 Virgil Security Inc.
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

#ifndef VIRGIL_SDK_CARD_H
#define VIRGIL_SDK_CARD_H

#include <memory>
#include <virgil/sdk/crypto/keys/PublicKey.h>
#include <virgil/sdk/cards/CardSignature.h>
#include <virgil/sdk/client/models/RawSignedModel.h>

namespace virgil {
    namespace sdk {
        namespace cards {
            class Card {
            public:
                Card(const std::string& identifier,
                     const std::string& identity,
                     const crypto::keys::PublicKey& publicKey,
                     const std::string& version,
                     const std::time_t& createdAt,
                     const VirgilByteArray& contentSnapshot,
                     const bool& isOutdated = false,
                     const std::vector<cards::CardSignature>& signatures = std::vector<cards::CardSignature>(),
                     const std::shared_ptr<std::string>& previousCardId = nullptr,
                     const std::shared_ptr<Card>& previousCard = nullptr);

                const std::string& identifier() const;

                const std::string& identity() const;

                const crypto::keys::PublicKey& publicKey() const;

                const std::string& version() const;

                const std::time_t& createdAt() const;

                const VirgilByteArray& contentSnapshot() const;

                const bool& isOutdated() const;

                const std::vector<cards::CardSignature>& signatures() const;

                const std::shared_ptr<std::string>& previousCardId() const;

                const std::shared_ptr<Card>& previousCard() const;

                client::models::RawSignedModel getRawCard() const;

            private:
                std::string identifier_;
                std::string identity_;
                crypto::keys::PublicKey publicKey_;
                std::shared_ptr<std::string> previousCardId_;
                std::shared_ptr<Card> previousCard_;
                bool isOutdated_;
                std::string version_;
                std::time_t createdAt_;
                std::vector<cards::CardSignature> signatures_;
                VirgilByteArray contentSnapshot_;
            };
        }
    }
}

#endif //VIRGIL_SDK_CARD_H
