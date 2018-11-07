/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#include <string>

#include <nlohman/json.hpp>

#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/JsonUtils.h>
#include <virgil/sdk/serialization/JsonDeserializer.h>
#include <virgil/sdk/serialization/CanonicalSerializer.h>
#include <virgil/sdk/jwt/JwtBodyContent.h>
#include <ctime>

using json = nlohmann::json;

using virgil::sdk::jwt::JwtBodyContent;
using virgil::sdk::util::JsonKey;
using virgil::sdk::util::JsonUtils;

namespace virgil {
    namespace sdk {
        namespace serialization {
            /**
             * @brief JSONSerializer<JwtBodyContent> specialization.
             */
            template<>
            class JsonDeserializer<JwtBodyContent> {
            public:
                template<int FAKE = 0>
                static JwtBodyContent fromJson(const json &j) {
                    try {
                        std::string issuer = j[JsonKey::AppId];
                        std::string subject = j[JsonKey::IdentityJWT];

                        std::string appId = std::move(issuer.erase(0, 7));
                        std::string identity = std::move(subject.erase(0,9));
                        std::time_t issuedAt = j[JsonKey::IssuedAt];
                        std::time_t expiresAt = j[JsonKey::ExpiresAt];

                        json additionalDataJson = j.value(JsonKey::AdditionalData, json());
                        auto additionalData = JsonUtils::jsonToUnorderedMap(additionalDataJson);

                        return JwtBodyContent(appId, identity, expiresAt, issuedAt, additionalData);
                    } catch (std::exception &exception) {
                        throw std::logic_error(std::string("virgil-sdk:\n JsonDeserializer<JwtBodyContent>::fromJson ") +
                                               exception.what());
                    }
                }

                JsonDeserializer() = delete;
            };

            template<>
            class JsonSerializer<JwtBodyContent> {
            public:
                template<int INDENT = -1>
                static std::string toJson(const JwtBodyContent &bodyContent) {
                    try {
                        json j = {
                                {JsonKey::AppId, "virgil-" + bodyContent.appId()}
                        };

                        j[JsonKey::IdentityJWT] = "identity-" + bodyContent.identity();
                        j[JsonKey::IssuedAt] = bodyContent.issuedAt();
                        j[JsonKey::ExpiresAt] = bodyContent.expiresAt();

                        j[JsonKey::AdditionalData] = JsonUtils::unorderedMapToJson(bodyContent.additionalData());

                        return j.dump(INDENT);
                    } catch (std::exception &exception) {
                        throw std::logic_error(
                                std::string("virgil-sdk:\n JsonSerializer<JwtBodyContent>::toJson ")
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
template JwtBodyContent
virgil::sdk::serialization::JsonDeserializer<JwtBodyContent>::fromJson(const json&);

template std::string
virgil::sdk::serialization::JsonSerializer<JwtBodyContent>::toJson(const JwtBodyContent&);