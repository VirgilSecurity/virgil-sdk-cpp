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

#ifndef VIRGIL_SDK_CARD_H
#define VIRGIL_SDK_CARD_H

#include <memory>
#include <ctime>
#include <virgil/sdk/crypto/keys/PublicKey.h>
#include <virgil/sdk/cards/CardSignature.h>
#include <virgil/sdk/client/models/RawSignedModel.h>

namespace virgil {
    namespace sdk {
        namespace cards {
            /*!
             * @brief Class representing Virgil Card
             */
            class Card {
            public:
                /*!
                 * @brief Contructor
                 * @param identifier identifier of Virgil Card. Must be unique
                 * @param identity identity of Virgil Card
                 * @param publicKey Public Key of Virgil Card
                 * @param version version of Virgil Card
                 * @param createdAt std::time with creation date of Virgil Card
                 * @param contentSnapshot VirgilByteArray with snapshot of corresponding RawCardContent
                 * @param isOutdated true if Virgil Card is outdated, false otherwise
                 * @param signatures std::vector with CardSignatures of Virgil Card
                 * @param previousCardId identifier of outdated previous Virgil Card with same identity
                 * @param previousCard std::shared_ptr to previous Virgil Card instance
                 */
                Card(std::string identifier,
                     std::string identity,
                     crypto::keys::PublicKey publicKey,
                     std::string version,
                     std::time_t createdAt,
                     VirgilByteArray contentSnapshot,
                     bool isOutdated = false,
                     std::vector<cards::CardSignature> signatures = std::vector<cards::CardSignature>(),
                     std::string previousCardId = std::string(),
                     std::shared_ptr<Card> previousCard = nullptr);

                /*!
                 * @brief Getter
                 * @return identifier of Virgil Card
                 */
                const std::string& identifier() const;

                /*!
                 * @brief Getter
                 * @return identity of Virgil Card
                 */
                const std::string& identity() const;

                /*!
                 * @brief Getter
                 * @return Public Key of Virgil Card
                 */
                const crypto::keys::PublicKey& publicKey() const;

                /*!
                 * @brief Getter
                 * @return version of Virgil Card
                 */
                const std::string& version() const;

                /*!
                 * @brief Getter
                 * @return std::time with creation date of Virgil Card
                 */
                std::time_t createdAt() const;

                /*!
                 * @brief Getter
                 * @return VirgilByteArray with snapshot of corresponding RawCardContent
                 */
                const VirgilByteArray& contentSnapshot() const;

                /*!
                 * @brief Getter
                 * @return true if Virgil Card is outdated, false otherwise
                 */
                bool isOutdated() const;

                /*!
                 * @brief Getter
                 * @return identifier of outdated previous Virgil Card with same identity
                 */
                const std::string& previousCardId() const;

                /*!
                 * @brief Getter
                 * @return std::shared_ptr to previous Virgil Card instance
                 */
                const std::shared_ptr<Card>& previousCard() const;

                /*!
                 * @brief Getter
                 * @return std::vector with CardSignatures of Virgil Card
                 */
                const std::vector<cards::CardSignature>& signatures() const;

                /*!
                 * @brief Setter
                 * @param newIsOutdated bool isOutdated to be set
                 */
                void isOutdated(bool newIsOutdated);

                /*!
                 * @brief Setter
                 * @param newPreviousCardId std::string previousCardId to be set
                 */
                void previousCardId(const std::string& newPreviousCardId);

                /*!
                 * @brief Setter
                 * @param newPreviousCard previousCard to be set
                 */
                void previousCard(const std::shared_ptr<Card>& newPreviousCard);

                /*!
                 * @brief Builds RawSignedModel representing Card
                 * @return RawSignedModel representing Card
                 */
                client::models::RawSignedModel getRawCard() const;

            private:
                std::string identifier_;
                std::string identity_;
                crypto::keys::PublicKey publicKey_;
                std::string previousCardId_;
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