/**
 * Copyright (C) 2016 Virgil Security Inc.
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


#include <virgil/sdk/client/models/serialization/CanonicalSerializer.h>
#include <virgil/sdk/client/models/snapshotmodels/CreateCardSnapshotModel.h>

#include <map>
#include <string>
#include <stdexcept>

#include <nlohman/json.hpp>

#include <virgil/sdk/client/models/serialization/JsonSerializer.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/JsonUtils.h>
#include <virgil/sdk/client/models/Card.h>

using json = nlohmann::json;

using virgil::sdk::util::JsonKey;
using virgil::sdk::util::JsonUtils;
using virgil::sdk::client::models::snapshotmodels::CreateCardSnapshotModel;

namespace virgil {
    namespace sdk {
        namespace client {
            namespace models {
                namespace serialization {
                    template<>
                    class JsonSerializer<CreateCardSnapshotModel> {
                    public:
                        template<int INDENT = -1>
                        static std::string toJson(const CreateCardSnapshotModel &model) {
                            try {
                                json j = {
                                        {JsonKey::PublicKey, VirgilBase64::encode(model.publicKeyData())},
                                        {JsonKey::IdentityType, model.identityType()},
                                        {JsonKey::Identity, model.identity()},
                                        {JsonKey::CardScope, cardScopeToStr(model.scope())}
                                };

                                if (model.data().size() > 0) {
                                    j[JsonKey::Data] = model.data();
                                }

                                if (model.info().size() > 0) {
                                    j[JsonKey::Info] = model.info();
                                }

                                return j.dump(INDENT);
                            } catch (std::exception &exception) {
                                throw std::logic_error(std::string("virgil-sdk:\n JsonSerializer<CreateCardSnapshotModel>::toJson ") +
                                                       exception.what());
                            }
                        }

                        template<int FAKE = 0>
                        static CreateCardSnapshotModel fromJson(const std::string &jsonString) {
                            try {
                                auto j = json::parse(jsonString);

                                return CreateCardSnapshotModel(j[JsonKey::Identity],
                                                               j[JsonKey::IdentityType],
                                                               VirgilBase64::decode(j[JsonKey::PublicKey]),
                                                               JsonUtils::jsonToUnorderedMap(j[JsonKey::Data]),
                                                               strToCardScope(j[JsonKey::CardScope]),
                                                               JsonUtils::jsonToUnorderedMap(j[JsonKey::Info]));
                            } catch (std::exception &exception) {
                                throw std::logic_error(std::string("virgil-sdk:\n JsonSerializer<CreateCardSnapshotModel>::fromJson ") +
                                                       exception.what());
                            }
                        }

                    private:
                        JsonSerializer() {};
                    };

                    template<>
                    class CanonicalSerializer<CreateCardSnapshotModel> {
                    public:
                        template<int INDENT = -1>
                        static VirgilByteArray toCanonicalForm(const CreateCardSnapshotModel &model) {
                            try {
                                return VirgilByteArrayUtils::stringToBytes(JsonSerializer<CreateCardSnapshotModel>::toJson<INDENT>(model));
                            } catch (std::exception &exception) {
                                throw std::logic_error(std::string("virgil-sdk:\n CanonicalSerializer<CreateCardSnapshotModel>::toCanonicalForm ") +
                                                       exception.what());
                            }
                        }

                        template<int FAKE = 0>
                        static CreateCardSnapshotModel fromCanonicalForm(const VirgilByteArray &data) {
                            try {
                                return JsonSerializer<CreateCardSnapshotModel>::fromJson(VirgilByteArrayUtils::bytesToString(data));
                            } catch (std::exception &exception) {
                                throw std::logic_error(std::string("virgil-sdk:\n CanonicalSerializer<CreateCardSnapshotModel>::fromCanonicalForm ") +
                                                       exception.what());
                            }
                        }

                    private:
                        CanonicalSerializer() {};
                    };
                }
            }
        }
    }
}

/**
 * Explicit methods instantiation
 */
template std::string
virgil::sdk::client::models::serialization::JsonSerializer<CreateCardSnapshotModel>::toJson(const CreateCardSnapshotModel&);

template std::string
virgil::sdk::client::models::serialization::JsonSerializer<CreateCardSnapshotModel>::toJson<2>(const CreateCardSnapshotModel&);

template std::string
virgil::sdk::client::models::serialization::JsonSerializer<CreateCardSnapshotModel>::toJson<4>(const CreateCardSnapshotModel&);

template CreateCardSnapshotModel
virgil::sdk::client::models::serialization::JsonSerializer<CreateCardSnapshotModel>::fromJson(const std::string&);

template VirgilByteArray
virgil::sdk::client::models::serialization::CanonicalSerializer<CreateCardSnapshotModel>::toCanonicalForm(const CreateCardSnapshotModel&);

template VirgilByteArray
virgil::sdk::client::models::serialization::CanonicalSerializer<CreateCardSnapshotModel>::toCanonicalForm<2>(const CreateCardSnapshotModel&);

template VirgilByteArray
virgil::sdk::client::models::serialization::CanonicalSerializer<CreateCardSnapshotModel>::toCanonicalForm<4>(const CreateCardSnapshotModel&);

template CreateCardSnapshotModel
virgil::sdk::client::models::serialization::CanonicalSerializer<CreateCardSnapshotModel>::fromCanonicalForm(const VirgilByteArray&);
