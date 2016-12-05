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

#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/JsonUtils.h>
#include <virgil/sdk/client/models/serialization/JsonSerializer.h>
#include <virgil/sdk/client/models/serialization/CanonicalSerializer.h>
#include <virgil/sdk/client/models/snapshotmodels/RevokeCardSnapshotModel.h>

using json = nlohmann::json;

using virgil::sdk::util::JsonKey;
using virgil::sdk::util::JsonUtils;
using virgil::sdk::client::models::snapshotmodels::RevokeCardSnapshotModel;
using virgil::sdk::VirgilByteArray;

namespace virgil {
namespace sdk {
namespace client {
namespace models {
    namespace serialization {
        template<>
        class JsonSerializer<RevokeCardSnapshotModel> {
        public:
            template<int INDENT = -1>
            static std::string toJson(const RevokeCardSnapshotModel &model) {
                try {
                    json j = {
                            {JsonKey::CardId, model.cardId()},
                            {JsonKey::RevocationReason, cardRevocationReasonToStr(model.revocationReason())},
                    };

                    return j.dump(INDENT);
                } catch (std::exception &exception) {
                    throw std::logic_error(
                            std::string("virgil-sdk:\n JsonSerializer<RevokeCardSnapshotModel>::toJson ")
                            + exception.what());
                }
            }

            template<int FAKE = 0>
            static RevokeCardSnapshotModel fromJson(const json &j) {
                try {
                    return RevokeCardSnapshotModel::createModel(
                            j[JsonKey::CardId],
                            strToCardRevocationReason(j[JsonKey::RevocationReason]));
                } catch (std::exception &exception) {
                    throw std::logic_error(
                            std::string("virgil-sdk:\n JsonSerializer<RevokeCardSnapshotModel>::fromJson ")
                            + exception.what());
                }
            }

            JsonSerializer() = delete;
        };

        template<>
        class CanonicalSerializer<RevokeCardSnapshotModel> {
        public:
            template<int INDENT = -1>
            static VirgilByteArray toCanonicalForm(const RevokeCardSnapshotModel &model) {
                try {
                    return VirgilByteArrayUtils::stringToBytes(
                            JsonSerializer<RevokeCardSnapshotModel>::toJson<INDENT>(model));
                } catch (std::exception &exception) {
                    throw std::logic_error(
                            std::string("virgil-sdk:\n CanonicalSerializer<RevokeCardSnapshotModel>::toCanonicalForm ")
                            + exception.what());
                }
            }

            template<int FAKE = 0>
            static RevokeCardSnapshotModel foo(const std::string &jsonString) {
                return RevokeCardSnapshotModel::createModel("", CardRevocationReason::unspecified);
            }

            template<int FAKE = 0>
            static RevokeCardSnapshotModel fromCanonicalForm(const VirgilByteArray &data) {
                try {
                    return JsonSerializerBase<RevokeCardSnapshotModel>::fromJsonString(
                            VirgilByteArrayUtils::bytesToString(data));
                } catch (std::exception &exception) {
                    throw std::logic_error(
                            std::string("virgil-sdk:\n CanonicalSerializer<RevokeCardSnapshotModel>::fromCanonicalForm ")
                            + exception.what());
                }
            }

            CanonicalSerializer() = delete;
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
virgil::sdk::client::models::serialization::JsonSerializer<RevokeCardSnapshotModel>::toJson(const RevokeCardSnapshotModel&);

template std::string
virgil::sdk::client::models::serialization::JsonSerializer<RevokeCardSnapshotModel>::toJson<2>(const RevokeCardSnapshotModel&);

template std::string
virgil::sdk::client::models::serialization::JsonSerializer<RevokeCardSnapshotModel>::toJson<4>(const RevokeCardSnapshotModel&);

template RevokeCardSnapshotModel
virgil::sdk::client::models::serialization::JsonSerializer<RevokeCardSnapshotModel>::fromJson(const json&);

template VirgilByteArray
virgil::sdk::client::models::serialization::CanonicalSerializer<RevokeCardSnapshotModel>::toCanonicalForm(const RevokeCardSnapshotModel&);

template VirgilByteArray
virgil::sdk::client::models::serialization::CanonicalSerializer<RevokeCardSnapshotModel>::toCanonicalForm<2>(const RevokeCardSnapshotModel&);

template VirgilByteArray
virgil::sdk::client::models::serialization::CanonicalSerializer<RevokeCardSnapshotModel>::toCanonicalForm<4>(const RevokeCardSnapshotModel&);

template RevokeCardSnapshotModel
virgil::sdk::client::models::serialization::CanonicalSerializer<RevokeCardSnapshotModel>::fromCanonicalForm(const VirgilByteArray&);
