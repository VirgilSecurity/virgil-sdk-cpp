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

#ifndef VIRGIL_SDK_RAWSIGNEDMODEL_H
#define VIRGIL_SDK_RAWSIGNEDMODEL_H

#include <virgil/sdk/client/models/RawSignature.h>
#include <virgil/sdk/Common.h>
#include <vector>

namespace virgil {
    namespace sdk {
        namespace client {
            namespace models {
                /*!
                 * @brief Represents model in binary form which can have signatures and corresponds to Virgil Cards Service model
                 */
                class RawSignedModel {
                public:
                    /*!
                     * @brief Constructor
                     * @param contentSnapshot data with snapshot of RawCardContent
                     */
                    RawSignedModel(VirgilByteArray contentSnapshot);

                    /*!
                     * @brief Exports RawSignedModel as base64 encoded std::string
                     * @return base64 encoded std::string with RawSignedModel
                     */
                    std::string exportAsBase64EncodedString() const;

                    /*!
                     * @brief Exports RawSignedModel as json std::string
                     * @return json std::string with RawSignedModel
                     */
                    std::string exportAsJson() const;

                    /*!
                     * @brief Initializes RawSignedModel from base64 encoded std::string
                     * @param data base64 encoded std::string with RawSignedModel
                     * @return RawSignedModel instance
                     */
                    static RawSignedModel importFromBase64EncodedString(const std::string &data);

                    /*!
                     * @brief Initializes RawSignedModel from json std::string
                     * @param data json std::string with RawSignedModel
                     * @return RawSignedModel instance
                     */
                    static RawSignedModel importFromJson(const std::string &data);

                    /*!
                     * @brief Getter
                     * @return data with snapshot of RawCardContent
                     */
                    const VirgilByteArray& contentSnapshot() const;

                    /*!
                     * @brief Getter
                     * @return std::vector with RawSignatures of Card
                     */
                    const std::vector<RawSignature> signatures() const;

                    /*!
                     * @brief Adds new signature
                     * @param newSignature RawSignature to add
                     */
                    void addSignature(const RawSignature &newSignature);

                private:
                    VirgilByteArray contentSnapshot_;
                    std::vector<RawSignature> signatures_;
                };
            }
        }
    }
}

#endif //VIRGIL_SDK_RAWSIGNEDMODEL_H