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

#include <virgil/sdk/serialization/JsonDeserializer.h>
#include <virgil/sdk/client/models/RawSignedModel.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/JsonUtils.h>

using json = nlohmann::json;

using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::util::JsonKey;
using virgil::sdk::util::JsonUtils;

namespace virgil {
    namespace sdk {
        namespace serialization {
            /**
             * @brief JSONSerializer<std::vector<RawSignedModel>> specialization.
             */
            template<>
            class JsonDeserializer<std::vector<RawSignedModel>> {
            public:
                template<int FAKE = 0>
                static std::vector<RawSignedModel> fromJson(const json &j) {
                    try {
                        std::vector<RawSignedModel> response;
                        for (const auto& jElement : j) {
                            response.push_back(JsonDeserializer<RawSignedModel>::fromJson(jElement));
                        }

                        return response;
                    } catch (std::exception &exception) {
                        throw std::logic_error(std::string("virgil-sdk:\n JsonDeserializer<std::vector<RawSignedModel>>::fromJson ") +
                                               exception.what());
                    }
                }

                JsonDeserializer() = delete;
            };
        }
    }
}

/**
 * Explicit methods instantiation
 */
template std::vector<RawSignedModel>
virgil::sdk::serialization::JsonDeserializer<std::vector<RawSignedModel>>::fromJson(const json&);
