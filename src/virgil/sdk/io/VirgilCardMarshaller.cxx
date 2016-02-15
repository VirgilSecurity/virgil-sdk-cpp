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
#include <virgil/sdk/model/VirgilCard.h>
#include <virgil/sdk/model/CardIdentity.h>
#include <virgil/sdk/model/PublicKey.h>
#include <virgil/sdk/model/Identity.h>

using json = nlohmann::json;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::util::JsonKey;
using virgil::sdk::model::VirgilCard;
using virgil::sdk::model::CardIdentity;
using virgil::sdk::model::PublicKey;
using virgil::sdk::model::Identity;
using virgil::sdk::model::IdentityType;
using virgil::sdk::model::fromString;

namespace virgil {
namespace sdk {
    namespace io {
        /**
         * @brief Marshaller<VirgilCard> specialization.
         */
        template <> class Marshaller<VirgilCard> {
        public:
            template <int INDENT = -1> static std::string toJson(const VirgilCard& virgilCard) {
                try {
                    json jsonVirgilCard = {
                        {JsonKey::id, virgilCard.getId()},
                        {JsonKey::createdAt, virgilCard.getCreatedAt()},
                        {JsonKey::isConfirmed, virgilCard.isConfirmed()},
                        {JsonKey::hash, virgilCard.getHash()},
                    };

                    PublicKey publicKey = virgilCard.getPublicKey();
                    jsonVirgilCard[JsonKey::publicKey] = {
                        {JsonKey::id, publicKey.getId()},
                        {JsonKey::createdAt, publicKey.getCreatedAt()},
                        {JsonKey::publicKey, VirgilBase64::encode(publicKey.getKeyBytes())}};

                    CardIdentity cardIdentity = virgilCard.getCardIdentity();
                    jsonVirgilCard[JsonKey::identity] = {
                        {JsonKey::id, cardIdentity.getId()},
                        {JsonKey::type, virgil::sdk::model::toString(cardIdentity.getType())},
                        {JsonKey::value, cardIdentity.getValue()},
                        {JsonKey::isConfirmed, cardIdentity.isConfirmed()},
                        {JsonKey::createdAt, cardIdentity.getCreatedAt()}};

                    if (virgilCard.getData().empty()) {
                        jsonVirgilCard[JsonKey::data] = nullptr;
                    } else {
                        jsonVirgilCard[JsonKey::data] = virgilCard.getData();
                    }

                    return jsonVirgilCard.dump(INDENT);

                } catch (std::exception& exception) {
                    throw std::logic_error(std::string("virgil-sdk:\n Marshaller<VirgilCard>::toJson ") +
                                           exception.what());
                }
            }

            static VirgilCard fromJson(const std::string& jsonString) {
                try {
                    json jsonVirgilCard = json::parse(jsonString);

                    bool cardConfirmed = jsonVirgilCard[JsonKey::isConfirmed];
                    std::string cardId = jsonVirgilCard[JsonKey::id];
                    std::string cardCreatedAt = jsonVirgilCard[JsonKey::createdAt];
                    std::string cardHash = jsonVirgilCard[JsonKey::hash];

                    json jsonCardIdentity = jsonVirgilCard[JsonKey::identity];
                    bool identityConfirmed = jsonCardIdentity[JsonKey::isConfirmed];
                    std::string identityId = jsonCardIdentity[JsonKey::id];
                    std::string identityCreatedAt = jsonCardIdentity[JsonKey::createdAt];

                    std::string identityValue = jsonCardIdentity[JsonKey::value];
                    std::string identityValueString = jsonCardIdentity[JsonKey::type];
                    IdentityType identityType = fromString(identityValueString);

                    CardIdentity cardIdentity(identityId, identityCreatedAt, identityConfirmed, identityValue,
                                              identityType);

                    json jsonCustomData = jsonVirgilCard[JsonKey::data];
                    std::map<std::string, std::string> customData;
                    if (!jsonCustomData.is_null()) {
                        for (json::iterator it = jsonCustomData.begin(); it != jsonCustomData.end(); ++it) {
                            std::string key = it.key();
                            std::string val = it.value();
                            customData[key] = val;
                        }
                    }

                    json jsonPublicKey = jsonVirgilCard[JsonKey::publicKey];
                    std::string pubKeyId = jsonPublicKey[JsonKey::id];
                    std::string pubKeyCreatedAt = jsonPublicKey[JsonKey::createdAt];
                    VirgilByteArray publicKeyBytes = VirgilBase64::decode(jsonPublicKey[JsonKey::publicKey]);

                    PublicKey publicKey(pubKeyId, pubKeyCreatedAt, publicKeyBytes);

                    return VirgilCard(cardConfirmed, cardId, cardCreatedAt, cardHash, cardIdentity, customData,
                                      publicKey);

                } catch (std::exception& exception) {
                    throw std::logic_error(std::string("virgil-sdk:\n Marshaller<VirgilCard>::fromJson ") +
                                           exception.what());
                }
            }

        private:
            Marshaller(){};
        };

        std::string toJsonVirgilCards(const std::vector<virgil::sdk::model::VirgilCard> virgilCards, const int INDENT) {
            try {
                json jsonVirgilCards = json::array();
                for (const auto& virgilCard : virgilCards) {
                    std::string jsonVirgilCardStr = Marshaller<VirgilCard>::toJson(virgilCard);
                    json jsonVirgilCard = json::parse(jsonVirgilCardStr);
                    jsonVirgilCards.push_back(jsonVirgilCard);
                }

                return jsonVirgilCards.dump(INDENT);
            } catch (std::exception& exception) {
                throw std::logic_error(std::string("toJsonVirgilCards : ") + exception.what());
            }
        }

        std::vector<VirgilCard> fromJsonVirgilCards(const std::string& jsonStringVirgilCards) {
            try {
                json jsonResponseVirgilCards = json::parse(jsonStringVirgilCards);
                json jsonVirgilCards = jsonResponseVirgilCards;
                if (jsonResponseVirgilCards.find(JsonKey::virgilCards) != jsonResponseVirgilCards.end()) {
                    jsonVirgilCards = jsonResponseVirgilCards[JsonKey::virgilCards];
                }
                std::vector<VirgilCard> virgilCards;
                for (const auto& jsonVirgilCard : jsonVirgilCards) {
                    VirgilCard virgilCard = Marshaller<VirgilCard>::fromJson(jsonVirgilCard.dump());
                    virgilCards.push_back(virgilCard);
                }

                return virgilCards;

            } catch (std::exception& exception) {
                throw std::logic_error(std::string("fromJsonVirgilCards: ") + exception.what());
            }
        }
    }
}
}

void marshaller_virgil_card_init() {
    virgil::sdk::io::Marshaller<VirgilCard>::toJson(VirgilCard());
    virgil::sdk::io::Marshaller<VirgilCard>::toJson<2>(VirgilCard());
    virgil::sdk::io::Marshaller<VirgilCard>::toJson<4>(VirgilCard());
    virgil::sdk::io::Marshaller<VirgilCard>::fromJson(std::string());
}
