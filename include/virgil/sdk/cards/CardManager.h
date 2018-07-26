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

#ifndef VIRGIL_SDK_CARDMANAGER_H
#define VIRGIL_SDK_CARDMANAGER_H

#include <functional>
#include <virgil/sdk/jwt/interfaces/AccessTokenProviderInterface.h>
#include <virgil/sdk/cards/ModelSigner.h>
#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/sdk/cards/verification/CardVerifierInterface.h>
#include <virgil/sdk/client/CardClient.h>

using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::client::models::GetCardResponse;

namespace virgil {
    namespace sdk {
        namespace cards {
            /*!
             * @brief Class responsible for operations with Virgil Cards
             */
            class CardManager {
            public:
                /*!
                 * @brief Constructor
                 * @param crypto Crypto instance
                 * @param accessTokenProvider AccessTokenProviderInterface implementation used for getting Access Token
                 * when performing queries
                 * @param cardVerifier CardVerifierInterface implementation used for verifying Cards
                 * @param signCallback std::function called to perform additional signatures for card before publishing
                 * @param cardClient CardClientInterface implementation used for performing queries
                 * @param retryOnUnauthorized will automatically perform second query with forceReload = true AccessToken if true
                 */
                CardManager(std::shared_ptr<crypto::Crypto> crypto,
                            std::shared_ptr<jwt::interfaces::AccessTokenProviderInterface> accessTokenProvider,
                            std::shared_ptr<verification::CardVerifierInterface> cardVerifier,
                            std::function<std::future<RawSignedModel>(RawSignedModel)> signCallback = nullptr,
                            std::shared_ptr<client::CardClientInterface> cardClient = std::make_shared<client::CardClient>(),
                            bool retryOnUnauthorized = true);

                /*!
                 * @brief Generates self signed RawSignedModel
                 * @param crypto Crypto instance for exporting PublicKey
                 * @param modelSigner ModelSigner instance for self signing model
                 * @param privateKey PrivateKey to self sign with
                 * @param publicKey PublicKey instance
                 * @param identity identity of Card
                 * @param previousCardId identifier of Virgil Card with same identity this Card will replace
                 * @param extraFields std::unordered_map with extra data to sign with model
                 * @return self signed RawSignedModel
                 */
                static RawSignedModel generateRawCard(const std::shared_ptr<crypto::Crypto>& crypto, const ModelSigner& modelSigner,
                                                      const crypto::keys::PrivateKey& privateKey, const crypto::keys::PublicKey& publicKey,
                                                      const std::string& identity, const std::string& previousCardId = std::string(),
                                                      const std::unordered_map<std::string, std::string> &extraFields
                                                      = std::unordered_map<std::string, std::string>());

                /*!
                 * @brief Generates self signed RawSignedModel
                 * @param privateKey PrivateKey to self sign with
                 * @param publicKey PublicKey instance
                 * @param identity identity of Card
                 * @param previousCardId identifier of Virgil Card with same identity this Card will replace
                 * @param extraFields std::unordered_map with extra data to sign with model
                 * @return self signed RawSignedModel
                 */
                RawSignedModel generateRawCard(const crypto::keys::PrivateKey& privateKey, const crypto::keys::PublicKey& publicKey,
                                               const std::string& identity, const std::string& previousCardId = std::string(),
                                               const std::unordered_map<std::string, std::string> &extraFields
                                               = std::unordered_map<std::string, std::string>()) const;

                /*!
                 * @brief Imports Card from RawSignedModel
                 * @param model RawSignedModel instance to import
                 * @param crypto Crypto instance
                 * @return imported Card
                 */
                static Card parseCard(const RawSignedModel& model, const std::shared_ptr<crypto::Crypto>& crypto);

                /*!
                 * @brief Imports and verifies Card from RawSignedModel using self Crypto instance
                 * @param model RawSignedModel to import
                 * @return imported Card
                 */
                Card parseCard(const RawSignedModel& model) const;

                /*!
                 * @brief Asynchronously creates Virgil Card instance on the Virgil Cards Service and associates it with unique identifier
                 * Also makes the Card accessible for search/get queries from other users
                 * RawSignedModel should be at least selfSigned
                 * @param rawCard self signed RawSignedModel
                 * @return std::future with published and verified Card
                 */
                std::future<Card> publishCard(const RawSignedModel& rawCard) const;

                /*!
                 * @brief Generates self signed RawSignedModel, asynchronously creates Virgil Card
                 * instance on the Virgil Cards Service and associates it with unique identifier
                 * @param privateKey PrivateKey to self sign RawSignedModel with
                 * @param publicKey PublicKey instance for generating RawSignedModel
                 * @param identity identity for generating RawSignedModel. Will be taken from token if omitted
                 * @param previousCardId identifier of Virgil Card to replace
                 * @param extraFields std::unordered_map with extra data to sign RawSignedModel with
                 * @return std::future with published and verified Card
                 */
                std::future<Card> publishCard(const crypto::keys::PrivateKey& privateKey,
                                              const crypto::keys::PublicKey& publicKey,
                                              const std::string& identity = std::string(),
                                              const std::string& previousCardId = std::string(),
                                              const std::unordered_map<std::string, std::string>& extraFields
                                              = std::unordered_map<std::string, std::string>()) const;

                /*!
                 * @brief Asynchronously returns Card with given identifier
                 * @param cardId identifier of card to return
                 * @return std::future with found and verified Card
                 */
                std::future<Card> getCard(const std::string& cardId) const;

                /*!
                 * @brief Asynchronously performs search of Virgil Cards using identity on the Virgil Cards Service
                 * @param identity identity of Card to search
                 * @return std::future with std::vector of found and verified Cards
                 */
                std::future<std::vector<Card>> searchCards(const std::string& identity) const;

                /*!
                 * @brief Imports and verifies Card from base64 encoded std::string
                 * @param base64 base64 encoded std::string with Card
                 * @return imported and verified Card
                 */
                Card importCardFromBase64(const std::string& base64) const;

                /*!
                 * @brief Imports and verifies Card from json std::string
                 * @param json std::string with json structure of Card
                 * @return imported and verified Card
                 */
                Card importCardFromJson(const std::string json) const;

                /*!
                 * @brief Imports and verifies Card from RawSignedModel
                 * @param rawCard RawSignedModel to import
                 * @return imported and verified Card
                 */
                Card importCardFromRawCard(const RawSignedModel& rawCard) const;

                /*!
                 * @brief Exports Card as base64 encoded std::string
                 * @param card Card instance to export
                 * @return base64 encoded std::string with Card
                 */
                std::string exportCardAsBase64(const Card& card) const;

                /*!
                 * @brief Exports Card as json std::string
                 * @param card Card instance to import
                 * @return json std::string with Card
                 */
                std::string exportCardAsJson(const Card& card) const;

                /*!
                 * @brief Exports Card as RawSignedModel
                 * @param card Card instance to export
                 * @return RawSignedModel representing Card
                 */
                RawSignedModel exportCardAsRawCard(const Card& card) const;

                /*!
                 * @brief Getter
                 * @return std::shared_ptr to Crypto instance
                 */
                const std::shared_ptr<crypto::Crypto>& crypto() const;

                /*!
                 * @brief Getter
                 * @return std::shared_ptr to AccessTokenProviderInterface implementation
                 */
                const std::shared_ptr<jwt::interfaces::AccessTokenProviderInterface>& accessTokenProvider() const;

                /*!
                 * @brief Getter
                 * @return std::shared_ptr to CardVerifierInterface implementation
                 */
                const std::shared_ptr<verification::CardVerifierInterface>& cardVerifier() const;

                /*!
                 * @brief Getter
                 * @return ModelSigner instance
                 */
                const ModelSigner& modelSigner() const;

                /*!
                 * @brief Getter
                 * @return std::shared_ptr to CardClientInterface implementation
                 */
                const std::shared_ptr<client::CardClientInterface>& cardClient() const;

                /*!
                 * @brief Getter
                 * @return std::function called to perform additional signatures for card before publishing
                 */
                const std::function<std::future<RawSignedModel>(RawSignedModel)>& signCallback() const;

                /*!
                 * @brief Getter
                 * @return true if CardManager will automatically perform second query with forceReload = true AccessToken, false otherwise
                 */
                bool retryOnUnauthorized() const;

            private:
                std::shared_ptr<crypto::Crypto> crypto_;
                ModelSigner modelSigner_;
                std::shared_ptr<jwt::interfaces::AccessTokenProviderInterface> accessTokenProvider_;
                std::shared_ptr<verification::CardVerifierInterface> cardVerifier_;
                std::shared_ptr<client::CardClientInterface> cardClient_;
                std::function<std::future<RawSignedModel>(RawSignedModel)> signCallback_;
                bool retryOnUnauthorized_;

                template<typename T> T tryQuery(const jwt::TokenContext &tokenContext, const std::string& token,
                                                std::function<std::future<T>(const std::string& token)> query) const;

                bool validateSelfSignatures(const RawSignedModel& rawCard1, const RawSignedModel& rawCard2) const;
            };
        }
    }
}

#endif //VIRGIL_SDK_CARDMANAGER_H