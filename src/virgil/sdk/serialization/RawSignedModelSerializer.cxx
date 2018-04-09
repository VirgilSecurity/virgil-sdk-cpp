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

#include <string>

#include <nlohman/json.hpp>

#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/JsonUtils.h>
#include <virgil/sdk/serialization/JsonDeserializer.h>
#include <virgil/sdk/serialization/CanonicalSerializer.h>
#include <virgil/sdk/client/models/RawSignedModel.h>

using json = nlohmann::json;

using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::client::models::RawSignature;
using virgil::sdk::util::JsonKey;
using virgil::sdk::util::JsonUtils;

namespace virgil {
    namespace sdk {
        namespace serialization {
            /**
             * @brief JSONSerializer<RawSignedModel> specialization.
             */
            template<>
            class JsonDeserializer<RawSignedModel> {
            public:
                template<int FAKE = 0>
                static RawSignedModel fromJson(const json &j) {
                    try {
                        std::string snapshotStr = j[JsonKey::ContentSnapshot];

                        VirgilByteArray contentSnapshot = VirgilBase64::decode(snapshotStr);

                        json signaturesJson = j[JsonKey::Signatures];

                        auto rawCard = RawSignedModel(contentSnapshot);
                        for (auto& element : signaturesJson) {
                            std::string signer = element[JsonKey::Signer];

                            auto snapshotStr = element.value(JsonKey::Snapshot, std::string());
                            auto snapshot = VirgilBase64::decode(snapshotStr);

                            std::string signatureStr = element[JsonKey::Signature];
                            VirgilByteArray signatureBytes = VirgilBase64::decode(signatureStr);

                            auto signature = RawSignature(signer, signatureBytes, snapshot);
                            rawCard.addSignature(signature);
                        }

                        return rawCard;
                    } catch (std::exception &exception) {
                        throw std::logic_error(std::string("virgil-sdk:\n JsonDeserializer<RawSignedModel>::fromJson ") +
                                               exception.what());
                    }
                }

                JsonDeserializer() = delete;
            };

            template<>
            class JsonSerializer<RawSignedModel> {
            public:
                template<int INDENT = -1>
                static std::string toJson(const RawSignedModel &rawCard) {
                    try {
                        json j = {
                                {JsonKey::ContentSnapshot, VirgilBase64::encode(rawCard.contentSnapshot())}
                        };

                        json signatures = json::array();
                        for (auto& signature : rawCard.signatures()) {
                            json signatureJson = {
                                    {JsonKey::Signer, signature.signer()}
                            };
                            if (signature.snapshot().size() != 0) {
                                signatureJson[JsonKey::Snapshot] = VirgilBase64::encode(signature.snapshot());
                            }
                            signatureJson[JsonKey::Signature] = VirgilBase64::encode(signature.signature());
                            signatures.push_back(signatureJson);
                        }
                        j[JsonKey::Signatures] = signatures;

                        return j.dump(INDENT);
                    } catch (std::exception &exception) {
                        throw std::logic_error(
                                std::string("virgil-sdk:\n JsonSerializer<CardResponse>::toJson ")
                                + exception.what());
                    }
                }

                JsonSerializer() = delete;
            };
        }
    }
}

/**
 * Explicit methods instantiation
 */
template RawSignedModel
virgil::sdk::serialization::JsonDeserializer<RawSignedModel>::fromJson(const json&);

template std::string
virgil::sdk::serialization::JsonSerializer<RawSignedModel>::toJson(const RawSignedModel&);
