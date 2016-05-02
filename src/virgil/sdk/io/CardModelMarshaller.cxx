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

#include <map>
#include <string>
#include <stdexcept>

#include <json.hpp>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/io/Marshaller.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/dto/Identity.h>
#include <virgil/sdk/models/CardModel.h>
#include <virgil/sdk/models/IdentityModel.h>
#include <virgil/sdk/models/PublicKeyModel.h>

using json = nlohmann::json;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::util::JsonKey;
using virgil::sdk::dto::Identity;
using virgil::sdk::models::CardModel;
using virgil::sdk::models::IdentityModel;
using virgil::sdk::models::PublicKeyModel;
using virgil::sdk::models::fromString;

namespace virgil {
namespace sdk {
    namespace io {
        /**
         * @brief Marshaller<CardModel> specialization.
         */
        template <> class Marshaller<CardModel> {
        public:
            template <int INDENT = -1> static std::string toJson(const CardModel& card) {
                try {
                    json jsonCard = {
                        {JsonKey::id, card.getId()},
                        {JsonKey::createdAt, card.getCreatedAt()},
                        {JsonKey::authorizedBy, card.authorizedBy()},
                        {JsonKey::hash, card.getHash()},
                    };

                    PublicKeyModel publicKey = card.getPublicKey();
                    jsonCard[JsonKey::publicKey] = {{JsonKey::id, publicKey.getId()},
                                                    {JsonKey::createdAt, publicKey.getCreatedAt()},
                                                    {JsonKey::publicKey, VirgilBase64::encode(publicKey.getKey())}};

                    IdentityModel cardIdentity = card.getCardIdentity();
                    jsonCard[JsonKey::identity] = {
                        {JsonKey::id, cardIdentity.getId()},
                        {JsonKey::type, virgil::sdk::models::toString(cardIdentity.getType())},
                        {JsonKey::value, cardIdentity.getValue()},
                        {JsonKey::authorizedBy, cardIdentity.authorizedBy()},
                        {JsonKey::createdAt, cardIdentity.getCreatedAt()}};

                    if (card.getData().empty()) {
                        jsonCard[JsonKey::data] = nullptr;
                    } else {
                        jsonCard[JsonKey::data] = card.getData();
                    }

                    return jsonCard.dump(INDENT);

                } catch (std::exception& exception) {
                    throw std::logic_error(std::string("virgil-sdk:\n Marshaller<CardModel>::toJson ") +
                                           exception.what());
                }
            }

            static CardModel fromJson(const std::string& jsonString) {
                try {
                    json jsonCard = json::parse(jsonString);

                    bool cardConfirmed = jsonCard[JsonKey::authorizedBy];
                    std::string cardId = jsonCard[JsonKey::id];
                    std::string cardCreatedAt = jsonCard[JsonKey::createdAt];
                    std::string cardHash = jsonCard[JsonKey::hash];

                    json jsonCardIdentity = jsonCard[JsonKey::identity];
                    bool identityConfirmed = jsonCardIdentity[JsonKey::authorizedBy];
                    std::string identityId = jsonCardIdentity[JsonKey::id];
                    std::string identityCreatedAt = jsonCardIdentity[JsonKey::createdAt];

                    std::string identityValue = jsonCardIdentity[JsonKey::value];
                    std::string identityValueString = jsonCardIdentity[JsonKey::type];
                    IdentityModel::Type identityType = fromString(identityValueString);

                    IdentityModel cardIdentity(identityId, identityCreatedAt, identityConfirmed, identityValue,
                                               identityType);

                    json jsonCustomData = jsonCard[JsonKey::data];
                    std::map<std::string, std::string> customData;
                    if (!jsonCustomData.is_null()) {
                        for (json::iterator it = jsonCustomData.begin(); it != jsonCustomData.end(); ++it) {
                            std::string key = it.key();
                            std::string val = it.value();
                            customData[key] = val;
                        }
                    }

                    json jsonPublicKey = jsonCard[JsonKey::publicKey];
                    std::string pubKeyId = jsonPublicKey[JsonKey::id];
                    std::string pubKeyCreatedAt = jsonPublicKey[JsonKey::createdAt];
                    VirgilByteArray publicKeyBytes = VirgilBase64::decode(jsonPublicKey[JsonKey::publicKey]);

                    PublicKeyModel publicKey(pubKeyId, pubKeyCreatedAt, publicKeyBytes);

                    return CardModel(cardId, cardCreatedAt, cardHash, cardIdentity, customData, publicKey,
                                     cardConfirmed);

                } catch (std::exception& exception) {
                    throw std::logic_error(std::string("virgil-sdk:\n Marshaller<CardModel>::fromJson ") +
                                           exception.what());
                }
            }

        private:
            Marshaller(){};
        };

        std::string cardsToJson(const std::vector<virgil::sdk::models::CardModel> cards, const int INDENT) {
            try {
                json jsonCards = json::array();
                for (const auto& card : cards) {
                    std::string jsonCardStr = Marshaller<CardModel>::toJson(card);
                    json jsonCard = json::parse(jsonCardStr);
                    jsonCards.push_back(jsonCard);
                }

                return jsonCards.dump(INDENT);
            } catch (std::exception& exception) {
                throw std::logic_error(std::string("cardsToJson : ") + exception.what());
            }
        }

        std::vector<CardModel> cardsFromJson(const std::string& jsonStringCards) {
            try {
                json jsonResponseCards = json::parse(jsonStringCards);
                json jsonCards = jsonResponseCards;
                if (jsonResponseCards.find(JsonKey::cards) != jsonResponseCards.end()) {
                    jsonCards = jsonResponseCards[JsonKey::cards];
                }
                std::vector<CardModel> cards;
                for (const auto& jsonCard : jsonCards) {
                    CardModel card = Marshaller<CardModel>::fromJson(jsonCard.dump());
                    cards.push_back(card);
                }

                return cards;

            } catch (std::exception& exception) {
                throw std::logic_error(std::string("cardsFromJson: ") + exception.what());
            }
        }
    }
}
}

void marshaller_virgil_card_init() {
    virgil::sdk::io::Marshaller<CardModel>::toJson(CardModel());
    virgil::sdk::io::Marshaller<CardModel>::toJson<2>(CardModel());
    virgil::sdk::io::Marshaller<CardModel>::toJson<4>(CardModel());
    virgil::sdk::io::Marshaller<CardModel>::fromJson(std::string());
}
