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

#include <virgil/sdk/serialization/JsonDeserializer.h>
#include <virgil/sdk/client/networking/errors/VirgilError.h>
#include <virgil/sdk/util/JsonKey.h>

using json = nlohmann::json;

using virgil::sdk::util::JsonKey;
using virgil::sdk::client::networking::errors::VirgilError;

namespace virgil {
namespace sdk {
    namespace serialization {
        /**
         * @brief JSONSerializer<VirgilError> specialization.
         */
        template<>
        class JsonDeserializer<VirgilError> {
        public:
            template<int FAKE = 0>
            static VirgilError fromJson(const json &j) {
                try {
                    int errorCodeStr = j[JsonKey::Code];
                    std::string errorMsg = j[JsonKey::Message];

                    return VirgilError(errorCodeStr, errorMsg);
                } catch (std::exception &exception) {
                    throw std::logic_error(std::string("virgil-sdk:\n JsonDeserializer<VirgilError>::fromJson ") +
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
template VirgilError
virgil::sdk::serialization::JsonDeserializer<VirgilError>::fromJson(const json&);