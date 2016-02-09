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

#include <string>

#include <json.hpp>

#include <virgil/sdk/io/Marshaller.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/model/VirgilCard.h>
#include <virgil/sdk/model/VirgilCardIdentity.h>
#include <virgil/sdk/model/PublicKey.h>
#include <virgil/sdk/model/Identity.h>

#include <virgil/crypto/foundation/VirgilBase64.h>

using json = nlohmann::json;

using virgil::sdk::util::JsonKey;
using virgil::sdk::model::VirgilCard;
using virgil::sdk::model::VirgilCardIdentity;
using virgil::sdk::model::PublicKey;
using virgil::sdk::model::Identity;
using virgil::sdk::model::IdentityType;

using virgil::crypto::foundation::VirgilBase64;

using PairStrStr = std::pair<std::string, std::string>;


namespace virgil { namespace sdk { namespace io {
    /**
     * @brief Marshaller<VirgilCard> specialization.
     */
    template <>
    class Marshaller<VirgilCard> {
    public:
        template <int INDENT = -1>
        static std::string toJson(const VirgilCard& virgilCard) {
            json jsonVirgilCard = {
                { JsonKey::id, virgilCard.getId() },
                { JsonKey::createdAt, virgilCard.getCreatedAt() },
                { JsonKey::isConfirmed, virgilCard.isConfirmed() },
                { JsonKey::hash, virgilCard.getHash() },
            };

            PublicKey publicKey = virgilCard.getPublicKey();
            jsonVirgilCard[JsonKey::publicKey] = {
                { JsonKey::id, publicKey.getId() },
                { JsonKey::publicKey, publicKey.getKeyStr() },
                { JsonKey::createdAt, publicKey.getCreatedAt() }
            };

            VirgilCardIdentity virgilCardIdentity = virgilCard.getIdentity();
            Identity identity = virgilCardIdentity.getIdentity();
            jsonVirgilCard[JsonKey::identity] = {
                { JsonKey::id, virgilCardIdentity.getId() },
                { JsonKey::type, identity.getTypeAsString() },
                { JsonKey::value, identity.getValue() },
                { JsonKey::isConfirmed, virgilCardIdentity.isConfirmed() },
                { JsonKey::createdAt, virgilCardIdentity.getCreatedAt() }
            };

            std::vector<PairStrStr> customData = virgilCard.getData();
            json jsonCustomData;
            for(const auto& i: customData) {
                jsonCustomData[i.first] = i.second;
            }
            jsonVirgilCard[JsonKey::data] = jsonCustomData;
            return jsonVirgilCard.dump(INDENT);
        }

        static VirgilCard fromJson(const std::string& jsonString) {
            json jsonVirgilCard = json::parse(jsonString);

            VirgilCard virgilCard;
            virgilCard.setId( jsonVirgilCard[JsonKey::id] );
            virgilCard.setCreatedAt( jsonVirgilCard[JsonKey::createdAt] );
            virgilCard.setConfirme( jsonVirgilCard[JsonKey::isConfirmed] );
            virgilCard.setHash( jsonVirgilCard[JsonKey::hash] );

            json jsonPublicKey = jsonVirgilCard[JsonKey::publicKey];
            PublicKey publicKey;
            publicKey.setId( jsonPublicKey[JsonKey::id] );
            publicKey.setKeyStr( jsonPublicKey[JsonKey::publicKey] );
            publicKey.setCreatedAt( jsonPublicKey[JsonKey::createdAt] );
            virgilCard.setPublicKey(publicKey);

            json jsonVirgilCardIdentity = jsonVirgilCard[JsonKey::identity];
            std::string type = jsonVirgilCardIdentity[JsonKey::type];
            std::string value = jsonVirgilCardIdentity[JsonKey::value];
            IdentityType identityType = virgil::sdk::model::fromString(type);
            Identity identity(value, identityType);

            VirgilCardIdentity virgilCardIdentity;
            virgilCardIdentity.setIdentity(identity);
            virgilCardIdentity.setCreatedAt( jsonVirgilCardIdentity[JsonKey::createdAt] );
            virgilCardIdentity.setId( jsonVirgilCardIdentity[JsonKey::id] );
            virgilCardIdentity.setConfirme( jsonVirgilCardIdentity[JsonKey::isConfirmed] );
            virgilCard.setIdentity(virgilCardIdentity);

            json jsonCustomData = jsonVirgilCard[JsonKey::data];
            std::vector<PairStrStr> customData;
            for (json::iterator it = jsonCustomData.begin(); it != jsonCustomData.end(); ++it) {
                std::string key = it.key();
                std::string val = it.value();
                customData.push_back(std::make_pair(key, val));
            }
            virgilCard.setData(customData);
            return virgilCard;
        }

    private:
        Marshaller() {};
    };


    std::string toJsonVirgilCards(const std::vector<virgil::sdk::model::VirgilCard> virgilCards, const int INDENT) {
        json jsonVirgilCards;
        jsonVirgilCards = json::array();

        for(const auto& virgilCard : virgilCards) {
            json jsonVirgilCard = {
                { JsonKey::id, virgilCard.getId() },
                { JsonKey::createdAt, virgilCard.getCreatedAt() },
                { JsonKey::isConfirmed, virgilCard.isConfirmed() },
                { JsonKey::hash, virgilCard.getHash() },
            };

            PublicKey publicKey = virgilCard.getPublicKey();
            jsonVirgilCard[JsonKey::publicKey] = {
                { JsonKey::id, publicKey.getId() },
                { JsonKey::publicKey, publicKey.getKeyStr() },
                { JsonKey::createdAt, publicKey.getCreatedAt() }
            };

            VirgilCardIdentity virgilCardIdentity = virgilCard.getIdentity();
            Identity identity = virgilCardIdentity.getIdentity();
            jsonVirgilCard[JsonKey::identity] = {
                { JsonKey::id, virgilCardIdentity.getId() },
                { JsonKey::type, identity.getTypeAsString() },
                { JsonKey::value, identity.getValue() },
                { JsonKey::isConfirmed, virgilCardIdentity.isConfirmed() },
                { JsonKey::createdAt, virgilCardIdentity.getCreatedAt() }
            };

            std::vector<PairStrStr> customData = virgilCard.getData();
            json jsonCustomData;
            for(const auto& i: customData) {
                jsonCustomData[i.first] = i.second;
            }
            jsonVirgilCard[JsonKey::data] = jsonCustomData;

            jsonVirgilCards.push_back(jsonVirgilCard);
        }

        return jsonVirgilCards.dump(INDENT);
    }

    std::vector<VirgilCard> fromJsonVirgilCards(const std::string& jsonStringVirgilCards) {
        json jsonVirgilCards = json::parse(jsonStringVirgilCards);
        std::vector<VirgilCard> virgilCards;
        for(const auto& jsonVirgilCard: jsonVirgilCards) {
            VirgilCard virgilCard;
            virgilCard.setId( jsonVirgilCard[JsonKey::id] );
            virgilCard.setCreatedAt( jsonVirgilCard[JsonKey::createdAt] );
            virgilCard.setConfirme( jsonVirgilCard[JsonKey::isConfirmed] );
            virgilCard.setHash( jsonVirgilCard[JsonKey::hash] );

            json jsonPublicKey = jsonVirgilCard[JsonKey::publicKey];
            PublicKey publicKey;
            publicKey.setId( jsonPublicKey[JsonKey::id] );
            publicKey.setKeyStr( jsonPublicKey[JsonKey::publicKey] );
            publicKey.setCreatedAt( jsonPublicKey[JsonKey::createdAt] );
            virgilCard.setPublicKey(publicKey);

            json jsonVirgilCardIdentity = jsonVirgilCard[JsonKey::identity];
            std::string type = jsonVirgilCardIdentity[JsonKey::type];
            std::string value = jsonVirgilCardIdentity[JsonKey::value];
            IdentityType identityType = virgil::sdk::model::fromString(type);
            Identity identity(value, identityType);

            VirgilCardIdentity virgilCardIdentity;
            virgilCardIdentity.setIdentity(identity);
            virgilCardIdentity.setCreatedAt( jsonVirgilCardIdentity[JsonKey::createdAt] );
            virgilCardIdentity.setId( jsonVirgilCardIdentity[JsonKey::id] );
            virgilCardIdentity.setConfirme( jsonVirgilCardIdentity[JsonKey::isConfirmed] );
            virgilCard.setIdentity(virgilCardIdentity);

            json jsonCustomData = jsonVirgilCard[JsonKey::data];
            std::vector<PairStrStr> customData;
            for (json::iterator it = jsonCustomData.begin(); it != jsonCustomData.end(); ++it) {
                std::string key = it.key();
                std::string val = it.value();
                customData.push_back(std::make_pair(key, val));
            }
            virgilCard.setData(customData);

            virgilCards.push_back(virgilCard);
        }

        return virgilCards;
    }

}}}

void marshaller_virgil_card_init() {
    virgil::sdk::io::Marshaller<VirgilCard>::toJson(VirgilCard());
    virgil::sdk::io::Marshaller<VirgilCard>::toJson<2>(VirgilCard());
    virgil::sdk::io::Marshaller<VirgilCard>::toJson<4>(VirgilCard());
    virgil::sdk::io::Marshaller<VirgilCard>::fromJson("");
}
