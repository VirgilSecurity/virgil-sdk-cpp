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

#ifndef VIRGIL_SDK_CARDMANAGER_H
#define VIRGIL_SDK_CARDMANAGER_H

#include <functional>
#include <virgil/sdk/jwt/interfaces/AccessTokenProviderInterface.h>
#include <virgil/sdk/client/CardClientInterface.h>
#include <virgil/sdk/cards/ModelSigner.h>
#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/sdk/cards/verification/CardVerifierInterface.h>

using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::client::models::GetCardResponse;

namespace virgil {
    namespace sdk {
        namespace cards {
            class CardManager {
            public:
                CardManager(const std::shared_ptr<crypto::Crypto>& crypto,
                            const std::shared_ptr<jwt::interfaces::AccessTokenProviderInterface>& accessTokenProvider,
                            const std::shared_ptr<verification::CardVerifierInterface>& cardVerifier);

                RawSignedModel generateRawCard(const crypto::keys::PrivateKey& privateKey, const crypto::keys::PublicKey& publicKey,
                                               const std::string& identity, const std::string& previousCardId = std::string(),
                                               const std::unordered_map<std::string, std::string> &extraFields
                                               = std::unordered_map<std::string, std::string>()) const;

                static Card parseCard(const RawSignedModel& model, const std::shared_ptr<crypto::Crypto>& crypto);

                Card parseCard(const RawSignedModel& model) const;

                std::future<Card> publishCard(const RawSignedModel& rawCard) const;

                std::future<Card> publishCard(const crypto::keys::PrivateKey& privateKey,
                                              const crypto::keys::PublicKey& publicKey,
                                              const std::string& identity = std::string(),
                                              const std::string& previousCardId = std::string(),
                                              const std::unordered_map<std::string, std::string>& extraFields
                                              = std::unordered_map<std::string, std::string>()) const;

                std::future<Card> getCard(const std::string& cardId) const;

                std::future<std::vector<Card>> searchCards(const std::string& identity) const;

                Card importCardFromBase64(const std::string& base64) const;
                Card importCardFromJson(const std::string json) const;
                Card importCardFromRawCard(const RawSignedModel& rawCard) const;

                std::string exportCardAsBase64(const Card& card) const;
                std::string exportCardAsJson(const Card& card) const;
                RawSignedModel exportCardAsRawCard(const Card& card) const;

                const std::shared_ptr<crypto::Crypto>& crypto() const;
                const std::shared_ptr<jwt::interfaces::AccessTokenProviderInterface>& accessTokenProvider() const;
                const std::shared_ptr<verification::CardVerifierInterface>& cardVerifier() const;

                const ModelSigner& modelSigner() const;
                void modelSigner(const ModelSigner& newModelSigner);

                const std::shared_ptr<client::CardClientInterface>& cardClient() const;
                void cardClient(const std::shared_ptr<client::CardClientInterface>& newCardClient);

                const std::function<std::future<RawSignedModel>(RawSignedModel)>& signCallback() const;
                void signCallback(const std::function<std::future<RawSignedModel>(RawSignedModel)>& newSignCallback);

                const bool& retryOnUnauthorized() const;
                void retryOnUnauthorized(const bool& newRetryOnUnauthorized);

            private:
                ModelSigner modelSigner_;
                std::shared_ptr<crypto::Crypto> crypto_;
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
