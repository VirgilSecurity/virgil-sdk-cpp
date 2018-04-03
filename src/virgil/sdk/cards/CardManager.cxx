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

#include <map>
#include <virgil/sdk/cards/CardManager.h>
#include <virgil/sdk/client/CardClient.h>
#include <virgil/sdk/client/models/RawCardContent.h>
#include <virgil/sdk/util/JsonUtils.h>
#include <virgil/sdk/VirgilSdkError.h>

using virgil::sdk::cards::CardManager;
using virgil::sdk::jwt::interfaces::AccessTokenProviderInterface;
using virgil::sdk::client::CardClientInterface;
using virgil::sdk::cards::verification::CardVerifierInterface;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::crypto::keys::PrivateKey;
using virgil::sdk::crypto::keys::PublicKey;
using virgil::sdk::client::CardClient;
using virgil::sdk::cards::ModelSigner;
using virgil::sdk::client::models::RawCardContent;
using virgil::sdk::cards::Card;
using virgil::sdk::util::JsonUtils;
using virgil::sdk::make_error;
using virgil::sdk::jwt::TokenContext;
using virgil::sdk::client::networking::errors::Error;

using virgil::sdk::jwt::interfaces::AccessTokenInterface;

CardManager::CardManager(const virgil::sdk::crypto::Crypto &crypto,
                         const std::shared_ptr<AccessTokenProviderInterface> &accessTokenProvider,
                         const std::shared_ptr<CardVerifierInterface> &cardVerifier)
: crypto_(crypto), accessTokenProvider_(accessTokenProvider), cardVerifier_(cardVerifier),
  modelSigner_(ModelSigner(crypto_)), retryOnUnauthorized_(true) {
    cardClient_ = std::make_shared<CardClient>(CardClient());
}

RawSignedModel CardManager::generateRawCard(const PrivateKey &privateKey, const PublicKey &publicKey,
                                            const std::string& identity, const std::string &previousCardId,
                                            const std::unordered_map<std::string, std::string> &extraFields) const {
    auto exportedPublicKey = crypto_.exportPublicKey(publicKey);
    auto cardContent = RawCardContent(identity, exportedPublicKey, std::time_t(0));

    auto rawCard = RawSignedModel(cardContent.snapshot());
    modelSigner_.selfSign(rawCard, privateKey, extraFields);

    return rawCard;
}

std::future<Card> CardManager::publishCard(const RawSignedModel& rawCard) const {
    auto future = std::async([=]{
        auto cardContent = RawCardContent::parse(rawCard.contentSnapshot());
        auto tokenContext = TokenContext("publish", cardContent.identity());

        auto tokenFuture = accessTokenProvider_->getToken(tokenContext);

        auto rawSignedModel = rawCard;
        if (signCallback_ != nullptr) {
            rawSignedModel = signCallback_(rawCard).get();
        }

        auto publishedRawCard = tryPublish(tokenContext, rawSignedModel, tokenFuture.get()->stringRepresentation());

        if (publishedRawCard.contentSnapshot() != rawSignedModel.contentSnapshot()){
            throw make_error(VirgilSdkError::CardVerificationFailed, "Publishing returns invalid card");
        }

        auto card = parseCard(publishedRawCard);

        if (cardVerifier_ != nullptr) {
            if (!cardVerifier_->verifyCard(card))
                throw make_error(VirgilSdkError::CardVerificationFailed, "Card verification failed.");
        }

        return card;
    });

    return future;
}

std::future<Card> CardManager::publishCard(const virgil::sdk::crypto::keys::PrivateKey &privateKey,
                                           const virgil::sdk::crypto::keys::PublicKey &publicKey,
                                           const std::string &identity, const std::string &previousCardId,
                                           const std::unordered_map<std::string, std::string> &extraFields) const {
    auto future = std::async([=]{
        auto tokenContext = TokenContext("publish", identity);
        auto token = accessTokenProvider_->getToken(tokenContext).get();

        auto rawCard = generateRawCard(privateKey, publicKey, token->identity(), previousCardId, extraFields);

        auto rawSignedModel = rawCard;
        if (signCallback_ != nullptr) {
            rawSignedModel = signCallback_(rawCard).get();
        }

        auto publishedRawCard = tryPublish(tokenContext, rawSignedModel, token->stringRepresentation());

        if (publishedRawCard.contentSnapshot() != rawSignedModel.contentSnapshot()){
            throw make_error(VirgilSdkError::CardVerificationFailed, "Publishing returns invalid card");
        }

        auto card = parseCard(publishedRawCard);

        if (cardVerifier_ != nullptr) {
            if (!cardVerifier_->verifyCard(card))
                throw make_error(VirgilSdkError::CardVerificationFailed, "Card verification failed.");
        }

        return card;
    });

    return future;
}

RawSignedModel CardManager::tryPublish(const TokenContext &tokenContext, const RawSignedModel &rawCard,
                                       const std::string &token) const {
    try {
        auto futureResponse = cardClient_->publishCard(rawCard, token);

        return futureResponse.get();
    } catch (Error error) {
        if (error.httpErrorCode() == 401 && retryOnUnauthorized_) {
            auto newTokenContext = TokenContext(tokenContext.operation(), tokenContext.identity(), true);
            auto newTokenFuture = accessTokenProvider_->getToken(newTokenContext);
            auto newFutureResponse = cardClient_->publishCard(rawCard, newTokenFuture.get()->stringRepresentation());

            return newFutureResponse.get();
        } else
            throw make_error(VirgilSdkError::ServiceQueryFailed, error.errorMsg());
    }
}

std::future<Card> CardManager::getCard(const std::string &cardId) const {
    auto future = std::async([=]{
        auto tokenContext = TokenContext("get");
        auto tokenFuture = accessTokenProvider_->getToken(tokenContext);

        auto getCardResponse = tryGet(tokenContext, cardId, tokenFuture.get()->stringRepresentation());

        auto card = parseCard(getCardResponse.rawCard());
        card.isOutdated(getCardResponse.isOutdated());

        if (card.identifier() != cardId) {
            throw make_error(VirgilSdkError::CardVerificationFailed, "Get wrong card");
        }

        if (cardVerifier_ != nullptr) {
            if (!cardVerifier_->verifyCard(card))
                throw make_error(VirgilSdkError::CardVerificationFailed, "Card verification failed.");
        }

        return card;
    });

    return future;
}

GetCardResponse CardManager::tryGet(const virgil::sdk::jwt::TokenContext &tokenContext, const std::string &cardId,
                                    const std::string &token) const {
    try {
        auto futureResponse = cardClient_->getCard(cardId, token);

        return futureResponse.get();
    } catch (Error error) {
        if (error.httpErrorCode() == 401 && retryOnUnauthorized_) {
            auto newTokenContext = TokenContext(tokenContext.operation(), tokenContext.identity(), true);
            auto newTokenFuture = accessTokenProvider_->getToken(newTokenContext);
            auto newFutureResponse = cardClient_->getCard(cardId, newTokenFuture.get()->stringRepresentation());

            return newFutureResponse.get();
        } else
            throw make_error(VirgilSdkError::ServiceQueryFailed, error.errorMsg());
    }
}

std::future<std::vector<Card>> CardManager::searchCards(const std::string &identity) const {
    auto future = std::async([=]{
        auto tokenContext = TokenContext("search");
        auto tokenFuture = accessTokenProvider_->getToken(tokenContext);

        auto rawCards = trySearch(tokenContext, identity, tokenFuture.get()->stringRepresentation());

        auto cards = std::vector<Card>();
        auto unsorted = std::map<std::string, std::shared_ptr<Card>>();
        for (auto& rawCard : rawCards) {
            auto card = parseCard(rawCard);
            if (card.identity() != identity) {
                throw make_error(VirgilSdkError::CardVerificationFailed, "Get wrong card");
            }
            if (cardVerifier_ != nullptr) {
                if (!cardVerifier_->verifyCard(card))
                    throw make_error(VirgilSdkError::CardVerificationFailed, "Card verification failed.");
            }

            unsorted[card.identifier()] = std::make_shared<Card>(card);
            cards.push_back(parseCard(rawCard));
        }

        for (std::vector<Card>::iterator card = cards.begin(); card != cards.end(); card++) {
            if (unsorted.find(card->previousCardId()) != unsorted.end()) {
                card->previousCard(unsorted[card->previousCardId()]);
                unsorted[card->previousCardId()]->isOutdated(true);
                unsorted.erase(card->previousCardId());
                cards.erase(card);
                card--;
            }
        }

        return cards;
    });

    return future;
}

std::vector<RawSignedModel> CardManager::trySearch(const virgil::sdk::jwt::TokenContext &tokenContext,
                                                   const std::string &identity, const std::string &token) const {
    try {
        auto futureResponse = cardClient_->searchCards(identity, token);

        return futureResponse.get();
    } catch (Error error) {
        if (error.httpErrorCode() == 401 && retryOnUnauthorized_) {
            auto newTokenContext = TokenContext(tokenContext.operation(), tokenContext.identity(), true);
            auto newTokenFuture = accessTokenProvider_->getToken(newTokenContext);
            auto newFutureResponse = cardClient_->searchCards(identity, newTokenFuture.get()->stringRepresentation());

            return newFutureResponse.get();
        } else
            throw make_error(VirgilSdkError::ServiceQueryFailed, error.errorMsg());
    }
}

Card CardManager::parseCard(const RawSignedModel &model, const Crypto& crypto) {
    auto rawCardContent = RawCardContent::parse(model.contentSnapshot());

    auto publicKey = crypto.importPublicKey(rawCardContent.publicKey());
    auto fingerprint = crypto.computeHash(model.contentSnapshot(), VirgilHashAlgorithm::SHA512);
    fingerprint.resize(32);
    auto cardId = VirgilByteArrayUtils::bytesToHex(fingerprint);

    auto cardSignatures = std::vector<CardSignature>();
    for (auto& rawSignature : model.signatures()) {
        auto extraFields = std::unordered_map<std::string, std::string>();
        if (rawSignature.snapshot().size() > 0)
            extraFields = JsonUtils::bytesToUnorderedMap(rawSignature.snapshot());

        auto cardSignature = CardSignature(rawSignature.signer(), rawSignature.signature(),
                                           rawSignature.snapshot(), extraFields);
        cardSignatures.push_back(cardSignature);
    }

    return Card(cardId, rawCardContent.identity(), publicKey, rawCardContent.version(),
                rawCardContent.createdAt(), model.contentSnapshot(), false, cardSignatures);
}

Card CardManager::parseCard(const RawSignedModel &model) const {
    return CardManager::parseCard(model, crypto_);
}

Card CardManager::importCardFromBase64(const std::string &base64) const {
    auto rawCard = RawSignedModel::importFromBase64EncodedString(base64);

    return CardManager::importCardFromRawCard(rawCard);
}

Card CardManager::importCardFromJson(const std::string json) const {
    auto rawCard = RawSignedModel::importFromJson(json);

    return CardManager::importCardFromRawCard(rawCard);
}

Card CardManager::importCardFromRawCard(const RawSignedModel &rawCard) const {
    auto card = parseCard(rawCard);

    if (!cardVerifier_->verifyCard(card)) {
        throw make_error(VirgilSdkError::CardVerificationFailed, "Card verification failed.");
    }

    return card;
}

std::string CardManager::exportCardAsBase64(const virgil::sdk::cards::Card &card) const {
    return card.getRawCard().exportAsBase64EncodedString();
}

std::string CardManager::exportCardAsJson(const virgil::sdk::cards::Card &card) const {
    return card.getRawCard().exportAsJson();
}

RawSignedModel CardManager::exportCardAsRawCard(const virgil::sdk::cards::Card &card) const {
    return card.getRawCard();
}

const Crypto& CardManager::crypto() const { return crypto_; }

const std::shared_ptr<AccessTokenProviderInterface> & CardManager::accessTokenProvider() const { return accessTokenProvider_; }

const std::shared_ptr<CardVerifierInterface> & CardManager::cardVerifier() const { return cardVerifier_; }

const ModelSigner& CardManager::modelSigner() const { return modelSigner_; }

const std::shared_ptr<CardClientInterface> & CardManager::cardClient() const { return cardClient_; }

const std::function<std::future<RawSignedModel>(RawSignedModel)>& CardManager::signCallback() const { return signCallback_; }

const bool& CardManager::retryOnUnauthorized() const { return retryOnUnauthorized_; }

void CardManager::modelSigner(const virgil::sdk::cards::ModelSigner &newModelSigner) {
    modelSigner_ = newModelSigner;
}

void CardManager::cardClient(const std::shared_ptr<CardClientInterface> &newCardClient) {
    cardClient_ = newCardClient;
}

void CardManager::signCallback(const std::function<std::future<RawSignedModel>(RawSignedModel)> &newSignCallback) {
    signCallback_ = newSignCallback;
}

void CardManager::retryOnUnauthorized(const bool &newRetryOnUnauthorized) {
    retryOnUnauthorized_ = newRetryOnUnauthorized;
}

