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
#include <virgil/sdk/client/models/serialization/JsonDeserializer.h>
#include <virgil/sdk/client/models/serialization/CanonicalSerializer.h>
#include <virgil/sdk/client/models/RawSignature.h>

using json = nlohmann::json;

using virgil::sdk::client::models::RawSignature;
using virgil::sdk::util::JsonKey;
using virgil::sdk::util::JsonUtils;

namespace virgil {
    namespace sdk {
        namespace client {
            namespace models {
                namespace serialization {
                    /**
                     * @brief JSONSerializer<RawSignature> specialization.
                     */
                    template<>
                    class JsonDeserializer<RawSignature> {
                    public:
                        template<int FAKE = 0>
                        static RawSignature fromJson(const json &j) {
                            try {
                                std::string signer = j[JsonKey::Signer];

                                std::shared_ptr<VirgilByteArray> snapshotPtr = nullptr;
                                try {
                                    std::string snapshotStr = j.at(JsonKey::Snapshot);
                                    VirgilByteArray snapshot = VirgilBase64::decode(snapshotStr);
                                    snapshotPtr = std::make_shared<VirgilByteArray>(snapshot);
                                } catch (std::exception &exception) {}

                                std::string signatureStr = j[JsonKey::Signature];
                                VirgilByteArray signature = VirgilBase64::decode(signatureStr);

                                return RawSignature(signer, signature, snapshotPtr);
                            } catch (std::exception &exception) {
                                throw std::logic_error(std::string("virgil-sdk:\n JsonDeserializer<RawSignature>::fromJson ") +
                                                       exception.what());
                            }
                        }

                        JsonDeserializer() = delete;
                    };

                    template<>
                    class JsonSerializer<RawSignature> {
                    public:
                        template<int INDENT = -1>
                        static std::string toJson(const RawSignature &rawSignature) {
                            try {
                                json j = {
                                        {JsonKey::Signer, rawSignature.signer()}
                                };

                                if (rawSignature.snapshot() != nullptr) {
                                    j[JsonKey::Snapshot] = VirgilBase64::encode(*rawSignature.snapshot());
                                }

                                j[JsonKey::Signature] = VirgilBase64::encode(rawSignature.signature());

                                return j.dump(INDENT);
                            } catch (std::exception &exception) {
                                throw std::logic_error(
                                        std::string("virgil-sdk:\n JsonSerializer<RawSignature>::toJson ")
                                        + exception.what());
                            }
                        }

                        JsonSerializer() = delete;
                    };
                }
            }
        }
    }
}

/**
 * Explicit methods instantiation
 */
template RawSignature
virgil::sdk::client::models::serialization::JsonDeserializer<RawSignature>::fromJson(const json&);

template std::string
virgil::sdk::client::models::serialization::JsonSerializer<RawSignature>::toJson(const RawSignature&);
