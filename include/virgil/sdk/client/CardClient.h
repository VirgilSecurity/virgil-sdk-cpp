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

#ifndef VIRGIL_SDK_CARDS_CLIENT_H
#define VIRGIL_SDK_CARDS_CLIENT_H

#include <map>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/Credentials.h>
#include <virgil/sdk/model/Card.h>
#include <virgil/sdk/model/ValidatedIdentity.h>
#include <virgil/sdk/model/CardSign.h>
#include <virgil/sdk/client/Client.h>

namespace virgil {
namespace sdk {
    namespace client {
        /**
         * @brief Provide access to the Virgil Keys Service endpoints,
         *        that perform managing of the Virgil Card entity
         */
        class CardClient : public Client {
        public:
            using Client::Client;
            /**
             * @brief Create client with ability to load self Virgil Card by request
             * @see Client::Client()
             */
            CardClient(const std::string& accessToken, const std::string& baseServiceUri);
            /**
             * @brief Create validated Virgil Card entity
             *
             * @param validatedIdentity - identity that was validated by user thru Virgil Identity Service
             * @param publicKey - Public Key that was generated locally
             * @param credentials - Private Key + Private Key password
             * @param customData - the custom data
             * @param toBeSignedCards - the map<cardId, cardHash> of hashes of card that need to sign
             * @return Created Virgil Card
             */
            virgil::sdk::model::Card
            create(const virgil::sdk::model::ValidatedIdentity& validatedIdentity,
                   const virgil::crypto::VirgilByteArray& publicKey, const virgil::sdk::Credentials& credentials,
                   const std::map<std::string, std::string>& customData = std::map<std::string, std::string>(),
                   const std::map<std::string, std::string>& toBeSignedCards = std::map<std::string, std::string>());
            /**
             * @brief Create validated Virgil Card entity attached to known public key
             *
             * @param validatedIdentity - identity that was validated by user thru Virgil Identity Service
             * @param publicKeyId - Public Key identifier
             * @param credentials - Private Key + Private Key password
             * @param customData - the custom data
             * @param toBeSignedCards - the map<cardId, cardHash> of hashes of card that need to sign
             * @return Created Virgil Card
             */
            virgil::sdk::model::Card
            create(const virgil::sdk::model::ValidatedIdentity& validatedIdentity, const std::string& publicKeyId,
                   const virgil::sdk::Credentials& credentials,
                   const std::map<std::string, std::string>& customData = std::map<std::string, std::string>(),
                   const std::map<std::string, std::string>& toBeSignedCards = std::map<std::string, std::string>());
            /**
             * @brief Creates not validated Virgil Card entity
             *
             * @param identity - identity to be searched
             * @param publicKey - Public Key that was generated locally
             * @param credentials - Private Key + Private Key password
             * @param customData - the custom data
             * @param toBeSignedCards - the map<cardId, cardHash> of hashes of card that need to sign.
             * @return Created Virgil Card
             */
            virgil::sdk::model::Card
            create(const virgil::sdk::model::Identity& identity, const virgil::crypto::VirgilByteArray& publicKey,
                   const virgil::sdk::Credentials& credentials,
                   const std::map<std::string, std::string>& customData = std::map<std::string, std::string>(),
                   const std::map<std::string, std::string>& toBeSignedCards = std::map<std::string, std::string>());
            /**
             * @brief Creates not validated Virgil Card entity attached to known public key
             *
             * @param identity - identity to be searched
             * @param publicKeyId - Public Key that was generated locally
             * @param credentials - Private Key + Private Key password
             * @param customData - the custom data
             * @param toBeSignedCards - the map<cardId, cardHash> of hashes of card that need to sign
             * @return Created Virgil Card
             */
            virgil::sdk::model::Card
            create(const virgil::sdk::model::Identity& identity, const std::string& publicKeyId,
                   const virgil::sdk::Credentials& credentials,
                   const std::map<std::string, std::string>& customData = std::map<std::string, std::string>(),
                   const std::map<std::string, std::string>& toBeSignedCards = std::map<std::string, std::string>());
            /**
             * @brief Sign another Virgil Card
             *
             * @details Signs another Virgil Card addressed in the request
             *          to share the information for the signed Virgil Card
             *
             * @param toBeSignedCardId - identifier of the Virgil Card that will be signed
             * @param toBeSignedCardHash - hash of the Virgil Card that will be signed
             * @param signerCardId - identifier of the signer's Virgil Card
             * @param signerCredentials - signer's Private Key that is connected to the signer's Virgil Card
             * @return Virgil Card Sign
             */
            virgil::sdk::model::CardSign sign(const std::string& toBeSignedCardId,
                                              const std::string& toBeSignedCardHash, const std::string& signerCardId,
                                              const Credentials& signerCredentials);
            /**
             * @brief Remove sign from another Virgil Card
             *
             * @details Discard chages made during @link sign() @endlink step.
             *
             * @param signedCardId - identifier of the Virgil Card that was signed
             * @param signOwnerCardId - identifier of the Virgil Card that was used for sign
             * @param signOwnerCredentials - signer's Private Key that is connected to the Virgil Card,
             *                               that was used for sign
             */
            void unsign(const std::string& signedCardId, const std::string& signOwnerCardId,
                        const virgil::sdk::Credentials& signOwnerCredentials);
            /**
             * @brief Performs the search of Virgil Cards
             *
             * @param identity - identity to be searched
             * @param relations - the list of Virgil Cards identifiers to perform the search within,
             *                    another word use this parameter to filter returned cards by signers
             * @param includeUnconfirmed - specifies whether an unconfirmed Virgil Cards should be returned
             * @return Found Virgil Cards
             */
            std::vector<virgil::sdk::model::Card>
            search(const virgil::sdk::model::Identity& identity,
                   const std::vector<std::string>& relations = std::vector<std::string>(),
                   const bool includeUnconfirmed = true);
            /**
             * @brief Performs the global search fot the applications' Virgil Cards
             *
             * @param applicationIdentity - application identity value, i.e. "com.virgilsecurity.keys",
             *                              or "com.virgilsecurity.*" to retreive Virgil Cards,
             *                              associated with some organization
             * @param skipVerification - skip verification of the service response;
             * @return Found Virgil Cards associated with application identity
             */
            std::vector<virgil::sdk::model::Card> searchApp(const std::string& applicationIdentity,
                                                            bool skipVerification = false) const;
            /**
             * @brief Revoke validated the Virgil Card and all associated data
             *
             * @param cardId - Virgil Card Identifier
             * @param validatedIdentity - entity that is validated via Virgil Identity Service,
             *                            and associted with given cardId
             * @param credentials - Private Key that associted with given cardId
             */
            void revoke(const std::string& cardId, const virgil::sdk::model::ValidatedIdentity& validatedIdentity,
                        const virgil::sdk::Credentials& credentials);
            /**
             * @brief Revoke not validated the Virgil Card and all associated data
             *
             * @param cardId - Virgil Card Identifier
             * @param identity - identity to be searched
             * @param credentials - Private Key that associted with given cardId
             */
            void revoke(const std::string& cardId, const virgil::sdk::model::Identity& identity,
                        const virgil::sdk::Credentials& credentials);
            /**
             * @brief Return card associated with given identifier
             *
             * @param cardId - Virgil Card identifier
             */
            virgil::sdk::model::Card get(const std::string& cardId);
            /**
             * @brief Return Virgil Cards associated with given Public Key identifier
             *
             * @param publicKeyId - Public Key identifier
             * @param cardId - one of the Virgil Card identifier associated with given Public Key identifier
             * @param credentials - Private Key that associted with given cardId
             * @return Virgil Cards associated with given publicKeyId
             */
            std::vector<virgil::sdk::model::Card> get(const std::string& publicKeyId, const std::string& cardId,
                                                      const Credentials& credentials);

        private:
            /**
             * @brief Support function for Card create(...)
             *
             * @param credentials - Private Key + Private Key password
             * @param jsonPayload - json body
             * @param toBeSignedCards - the map of hashes of card that need to sign
             * @return Created Virgil Card
             */
            virgil::sdk::model::Card create(const virgil::sdk::Credentials& credentials, const std::string& payload,
                                            const std::map<std::string, std::string>& toBeSignedCards);
        };
    }
}
}

#endif /* VIRGIL_SDK_CARDS_CLIENT_H */
