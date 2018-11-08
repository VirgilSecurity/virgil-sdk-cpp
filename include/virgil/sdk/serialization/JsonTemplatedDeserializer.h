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

#ifndef VIRGIL_SDK_JSONTEMPLATEDDESERIALIZER_H
#define VIRGIL_SDK_JSONTEMPLATEDDESERIALIZER_H

#include <nlohman/json.hpp>

namespace virgil {
namespace sdk {
    namespace serialization {
        /// Forward decl
        template<typename T>
        class JsonTemplatedDeserializer;

        /*!
        * @brief Base class for JsonTemplatedDeserializer.
        * @tparam T Class to be deserialized
        */
        template <typename T>
        class JsonTemplatedDeserializerBase {
        public:
            /*!
             *
             * @tparam ResultType type for deserialized objects. Supported classes: CreateCardRequest,
             *         RevokeCardRequest.
             * @param jsonString json representation of the object in std::string form
             * @return deserialized object
             */
            template<typename ResultType>
            static ResultType fromJsonString(const std::string &jsonString) {
                return JsonTemplatedDeserializer<T>::template fromJson<ResultType>(nlohmann::json::parse(jsonString));
            }
        };

        /*!
         * @brief This class is responsible for deserializing of templated models.
         * @note Supported classes: SignableRequestInterface
         * @tparam T
         */
        template<typename T>
        class JsonTemplatedDeserializer: public JsonTemplatedDeserializerBase<T> {
        public:
            /*!
             *
             * @tparam ResultType type for deserialized objects. Supported classes: CreateCardRequest,
             *         RevokeCardRequest.
             * @param json json representation of the object
             * @return deserialized object
             */
            template<typename ResultType>
            static ResultType fromJson(const nlohmann::json &json);

            /*!
             * @brief Forbid instantiation.
             */
            JsonTemplatedDeserializer() = delete;
        };
    }
}
}

#endif //VIRGIL_SDK_JSONTEMPLATEDDESERIALIZER_H