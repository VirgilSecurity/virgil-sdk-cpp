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
#include <vector>

#include "helpers.h"

#include <virgil/sdk/model/VirgilCardIdentity.h>

using virgil::sdk::model::PublicKey;
using virgil::sdk::model::PrivateKey;
using virgil::sdk::model::IdentityToken;
using virgil::sdk::model::Identity;
using virgil::sdk::model::IdentityType;
using virgil::sdk::model::VirgilCard;
using virgil::sdk::model::VirgilCardIdentity;
using virgil::sdk::model::TrustCardResponse; 
using virgil::sdk::util::JsonKey;   

using json = nlohmann::json;

using PairStrStr = std::pair<std::string, std::string>;


namespace virgil { namespace test {

      PublicKey getPubKey() {
            return PublicKey("e33898de-6302-4756-8f0c-5f6c5218e02e", "2015-12-22T07:03:42+0000","HaisUjRlcTY0cipNcUp");
        }

        json getJsonPubKey() {
            PublicKey publicKey = virgil::test::getPubKey();
            json jsonPublicKey = {
                { JsonKey::id, publicKey.getId() },
                { JsonKey::publicKey, publicKey.getKeyStr() },
                { JsonKey::createdAt, publicKey.getCreatedAt() }
            };
            return jsonPublicKey;
        }

      PrivateKey getPrvKey() {
            std::string virgilCardId = "57e0a766-28ef-355e-7ca2-d8a2dcf23fc4";
            std::string privateKeyBase64 =
                    "-----BEGIN EC PRIVATE KEY-----"
                    "MIHbAgEBBEEAgZH5dMUXx7qJ3En0Y1/WdPkuhT4GNiDO29Vpa3nKuLhmWfsSsdSa"
                    "RDY58ToL/VS+U8I9WJl+xec1GK9Yj+uyU6ALBgkrJAMDAggBAQ2hgYUDgYIABC98"
                    "WzVmV2zddeqrQ/VZieMfEstq3Gp4oXDzKYm91Jmo1ts10PsmairLwDxw25CPeN2l"
                    "kDYyISVXXtIkPKgCk81QJzoUxXAIB6l8btBrK5fP5RiqCqO8dcbG4/ybTLZvdeyI"
                    "K90m28BOpjX2ay9k68WEydV9gDbnqS+o+bnXrbv9"
                    "-----END EC PRIVATE KEY-----";

            return PrivateKey(virgilCardId, privateKeyBase64);
        }

        json getJsonPrvKey() {
            PrivateKey privateKey = virgil::test::getPrvKey();
            json jsonPrivateKey = {
                { JsonKey::virgilCardId, privateKey.getVirgilCardId() },
                { JsonKey::privateKey, privateKey.getKeyStr() }
            };
            return jsonPrivateKey;
        }


      IdentityToken getIdentityToken() {
            Identity identity("user@virgilsecurity.com", IdentityType::Email);
            std::string validationToken = "QwaVl3alF";

            return IdentityToken(identity, validationToken);
        }

        json getJsonIdentityToken() {
            IdentityToken identityToken = virgil::test::getIdentityToken();
            json jsonIdentityToken = {
                { JsonKey::type, identityToken.getIdentity().getTypeAsString() },
                { JsonKey::value, identityToken.getIdentity().getValue() },
                { JsonKey::validationToken, identityToken.getValidationToken() }
            };

            return jsonIdentityToken;
        }

        VirgilCard getVirgilCard() {
            std::string hash =
                    "hash";

            VirgilCardIdentity virgilCardIdentity(true, "607bc05d-3810-4e60-9ccd-0d0c4842350b",
                    "2015-12-22T07:03:42+0000",
                    Identity("username@virgilsecurity.com", IdentityType::Email));

            std::vector<PairStrStr> customData;
            customData.push_back(std::make_pair("parameter1", "value1"));
            customData.push_back(std::make_pair("parameter2", "value2"));

            PublicKey publicKey = virgil::test::getPubKey();

            return VirgilCard(true, "d4de27e5-361d-4b50-a40a-91de41727e22", "2015-12-22T07:03:42+0000", hash,
                    virgilCardIdentity, customData, publicKey);
        }

        json getJsonVirgilCard() {
            VirgilCard virgilCard = virgil::test::getVirgilCard();
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
            return jsonVirgilCard;
        }

        std::vector<VirgilCard> getVirgilCards() {
            std::vector<VirgilCard> virgilCards;
            virgilCards.push_back(virgil::test::getVirgilCard());
            virgilCards.push_back(virgil::test::getVirgilCard());
            return virgilCards;
        }

        nlohmann::json getResponseJsonVirgilCards() {
            PublicKey publicKey = virgil::test::getPubKey();

            json getResponse;
            getResponse[JsonKey::id] = publicKey.getId();
            getResponse[JsonKey::createdAt] = publicKey.getCreatedAt();
            getResponse[JsonKey::publicKey] = publicKey.getKeyStr();

            json jsonVirgilCard1 = virgil::test::getJsonVirgilCard();
            json jsonVirgilCard2 = virgil::test::getJsonVirgilCard();

            json jsonVirgilCards = json::array( {jsonVirgilCard1, jsonVirgilCard2} );

            getResponse[JsonKey::virgilCards] = jsonVirgilCards;

            return getResponse;
        }

        TrustCardResponse getResponseTrustCardResponse() {
            return TrustCardResponse(
                    "9e0bb253-879b-4fbd-a504-829faae7e958",
                    "2015-12-22T07:03:42+0000",
                    "84a66d5b-a6c7-45e9-b87b-06d5ac53ed2c",
                    "9ab9d4a4-0440-499f-bdc6-f99c83f900dd",
                    "MIGZMA0GCWCGSAFlAwQCAgUABIGHMIGEAkAM29/DTFvTTDrab8hH7QDWGR6a5I"
                    "gq+4Qw39fg3mLXtRWCv2YG2D/fsIn+CcdtvsDNQT8aWjTBbbY+J0BZQV40AkBEl"
                    "UXjYBZINHiWsC/Q4yhgeRDjip9wGjpXqUH5FU38P8HqPIHCwJE/1ErhQzL6xdiR"
                    "UWXhXR+1PhNJ1H5DZV7j");
        }

        nlohmann::json getJsonResponseTrustCardResponse() {
            TrustCardResponse trustCardResponse = virgil::test::getResponseTrustCardResponse();
            json jsonTrustCardResponse = {
                { JsonKey::id, trustCardResponse.getId() },
                { JsonKey::createdAt, trustCardResponse.getCreatedAt() },
                { JsonKey::signerVirgilCardId, trustCardResponse.getSignedVirgilCardId() },
                { JsonKey::signedVirgilCardId, trustCardResponse.getSignedVirgilCardId() },
                { JsonKey::signedDigest, trustCardResponse.getSignedDigest() },
            };

            return jsonTrustCardResponse;
        }

}}
