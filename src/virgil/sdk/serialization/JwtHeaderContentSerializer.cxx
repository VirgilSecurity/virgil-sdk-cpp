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
#include <virgil/sdk/jwt/JwtHeaderContent.h>

using json = nlohmann::json;

using virgil::sdk::jwt::JwtHeaderContent;
using virgil::sdk::util::JsonKey;
using virgil::sdk::util::JsonUtils;

namespace virgil {
    namespace sdk {
        namespace serialization {
            /**
             * @brief JSONSerializer<JwtHeaderContent> specialization.
             */
            template<>
            class JsonDeserializer<JwtHeaderContent> {
            public:
                template<int FAKE = 0>
                static JwtHeaderContent fromJson(const json &j) {
                    try {
                        std::string keyIdentifier = j[JsonKey::KeyIdentifier];
                        std::string algorithm = j[JsonKey::Algorithm];
                        std::string type = j[JsonKey::Type];
                        std::string contentType = j[JsonKey::ContentType];

                        return JwtHeaderContent(keyIdentifier, algorithm, type, contentType);
                    } catch (std::exception &exception) {
                        throw std::logic_error(std::string("virgil-sdk:\n JsonDeserializer<JwtHeaderContent>::fromJson ") +
                                               exception.what());
                    }
                }

                JsonDeserializer() = delete;
            };

            template<>
            class JsonSerializer<JwtHeaderContent> {
            public:
                template<int INDENT = -1>
                static std::string toJson(const JwtHeaderContent &headerContent) {
                    try {
                        json j = {
                                {JsonKey::Algorithm, headerContent.algorithm()}
                        };

                        j[JsonKey::Type] = headerContent.type();
                        j[JsonKey::ContentType] = headerContent.contentType();
                        j[JsonKey::KeyIdentifier] = headerContent.keyIdentifier();

                        return j.dump(INDENT);
                    } catch (std::exception &exception) {
                        throw std::logic_error(
                                std::string("virgil-sdk:\n JsonSerializer<JwtHeaderContent>::toJson ")
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
template JwtHeaderContent
virgil::sdk::serialization::JsonDeserializer<JwtHeaderContent>::fromJson(const json&);

template std::string
virgil::sdk::serialization::JsonSerializer<JwtHeaderContent>::toJson(const JwtHeaderContent&);