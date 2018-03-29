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

#ifndef VIRGIL_SDK_CANONICALSERIALIZER_H
#define VIRGIL_SDK_CANONICALSERIALIZER_H

#include <string>
#include <vector>

#include <virgil/sdk/Common.h>
#include <virgil/sdk/serialization/JsonSerializer.h>

namespace virgil {
namespace sdk {
    namespace serialization {
        /**
         * @brief This class is responsible for serializing and deserializing models in Canonical Form.
         * @tparam T concrete subclass
         * @note Supported classes: CreateCardSnapshotModel, RevokeCardSnapshotModel
         */
        template<typename T>
        class CanonicalSerializer {
        public:
            /*!
             * @brief Serizalizes model to Canonical Form.
             * @tparam INDENT if > 0 - pretty print, 0 - only new lines, -1 - compact
             * @param model model to serialize
             * @return serialized representation of model
             */
            template<int INDENT = -1>
            static VirgilByteArray toCanonicalForm(const T &model) ;

            /*!
             * @brief Constructs object from its Canonical Form representation.
             * @tparam FAKE fake argument to allow template implementation in source file.
             * @param data Canonical representation of object
             * @return Constructed object
             */
            template<int FAKE = 0>
            static T fromCanonicalForm(const VirgilByteArray &data);

            /*!
             * @brief Forbid instantiation.
             */
            CanonicalSerializer() = delete;
        };
    }
}
}

#endif //VIRGIL_SDK_CANONICALSERIALIZER_H
