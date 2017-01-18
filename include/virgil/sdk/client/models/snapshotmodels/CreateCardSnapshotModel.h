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

#ifndef VIRGIL_SDK_CREATECARDSNAPSHOTMODEL_H
#define VIRGIL_SDK_CREATECARDSNAPSHOTMODEL_H

#include <string>
#include <unordered_map>

#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/models/ClientCommon.h>
#include <virgil/sdk/client/models/serialization/JsonSerializer.h>

namespace virgil {
namespace sdk {
namespace client {
namespace models {
    namespace snapshotmodels {
        /*!
         * @brief Model which contains basic Virgil Card data needed for Card Creation.
         */
        class CreateCardSnapshotModel {
        public:
            /*!
             * @brief Required within std::future
             */
            CreateCardSnapshotModel() = default;

            /*!
             * @brief Creates CreateCardSnapshotModel instance and initializes with given parameters.
             * @param identity std::string with Card identity
             * @param identityType std::string with Card identity type
             * @param publicKeyData raw representation of Card's public key
             * @param data std::unordered_map with custom user payload
             * @param scope CardScope (application or global)
             * @param info std::unordered_map with info about device on which Card was created
             * @return initialized CreateCardSnapshotModel instance
             */
            static CreateCardSnapshotModel createModel(const std::string &identity, const std::string &identityType,
                                                       const VirgilByteArray &publicKeyData,
                                                       const std::unordered_map<std::string, std::string> &data,
                                                       CardScope scope,
                                                       const std::unordered_map<std::string, std::string> &info);

            /*!
             * @brief Getter.
             * @return std::string with Card identity
             */
            const std::string& identity() const { return identity_; }

            /*!
             * @brief Getter.
             * @return std::string with Card identity type
             */
            const std::string& identityType() const { return identityType_; }

            /*!
             * @brief Getter.
             * @return raw representation of Card's public key
             */
            const VirgilByteArray & publicKeyData() const { return publicKeyData_; }

            /*!
             * @brief Getter.
             * @return std::unordered_map with custom user payload
             */
            const std::unordered_map<std::string, std::string>& data() const { return data_; }

            /*!
             * @brief Getter.
             * @return CardScope (application or global)
             */
            CardScope scope() const { return scope_; }

            /*!
             * @brief Getter.
             * @return std::unordered_map with info about device on which Card was created
             */
            const std::unordered_map<std::string, std::string>& info() const { return info_; }

        private:
            CreateCardSnapshotModel(std::string identity, std::string identityType, VirgilByteArray publicKeyData,
                                    std::unordered_map<std::string, std::string> data, CardScope scope,
                                    std::unordered_map<std::string, std::string> info);

            std::string identity_;
            std::string identityType_;
            VirgilByteArray publicKeyData_;
            std::unordered_map<std::string, std::string> data_;
            CardScope scope_;
            std::unordered_map<std::string, std::string> info_;
        };
    }
}
}
}
}

#endif //VIRGIL_SDK_CREATECARDSNAPSHOTMODEL_H
