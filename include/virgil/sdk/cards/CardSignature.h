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

#ifndef VIRGIL_SDK_CARDSIGNATURE_H
#define VIRGIL_SDK_CARDSIGNATURE_H

#include <string>
#include <unordered_map>
#include <virgil/sdk/Common.h>

namespace virgil {
    namespace sdk {
        namespace cards {
            /*!
             * @brief Class representing Virgil Card Signature
             */
            class CardSignature {
            public:
                /*!
                 * @brief Constructor
                 * @param signer identifier of signer
                 * @param signature signature data
                 * @param snapshot additional data
                 * @param extraFields std::unordered_map with additional data
                 * @note signer must be unique. Reserved values:
                 *   - Self verifier: "self"
                 *   - Virgil Service verifier: "virgil"
                 */
                CardSignature(std::string signer,
                              VirgilByteArray signature,
                              VirgilByteArray snapshot,
                              std::unordered_map<std::string, std::string> extraFields);

                /*!
                 * @brief Getter
                 * @return identifier of signer
                 */
                const std::string& signer() const;

                /*!
                 * @brief Getter
                 * @return signature data
                 */
                const VirgilByteArray& signature() const;

                /*!
                 * @brief Getter
                 * @return additional data
                 */
                const VirgilByteArray& snapshot() const;

                /*!
                 * @brief Getter
                 * @return std::unordered_map with additional data
                 */
                const std::unordered_map<std::string, std::string>& extraFields() const;

            private:
                std::string signer_;
                VirgilByteArray signature_;
                VirgilByteArray snapshot_;
                std::unordered_map<std::string, std::string> extraFields_;
            };
        }
    }
}

#endif //VIRGIL_SDK_CARDSIGNATURE_H