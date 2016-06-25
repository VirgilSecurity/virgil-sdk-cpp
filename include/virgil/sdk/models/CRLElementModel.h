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

#ifndef VIRGIL_SDK_MODELS_CRL_ELEMENT_MODEL_H
#define VIRGIL_SDK_MODELS_CRL_ELEMENT_MODEL_H

#include <string>
#include <map>

#include <virgil/sdk/models/IdentityModel.h>
#include <virgil/sdk/models/PublicKeyModel.h>

namespace virgil {
    namespace sdk {
        namespace models {
            /**
             * @brief Data object represent "Virgil Certificate Revocation List element" entity
             */
            class CRLElementModel {
            public:
                /**
                 * @brief Create empty non valid Virgil CRL Element
                 */
                CRLElementModel() = default;
                /**
                 * @brief Create Virgil CRL Element with all associated data
                 *
                 * @param id - Virgil CRL Element identifier
                 * @param revokedAt - certificate revocation timestamp
                 * @param identity - identity associated with revoked certificate
                 */
                CRLElementModel(const std::string& id,
                                const std::string& revokedAt,
                                const virgil::sdk::dto::Identity& identity);
                /**
                 * @brief Return Virgil CRL element identifier
                 */
                const std::string getId() const;
                /**
                 * @brief Return revocation timestamp
                 */
                const std::string getRevokedAt() const;
                /**
                 * @brief Return compressed information about Virgil Card
                 * @note This value can be used for signing
                 */
                const virgil::sdk::dto::Identity getIdentity() const;
                
            private:
                std::string id_;
                std::string revokedAt_;
                virgil::sdk::dto::Identity identity_;
            };
            /**
             * @brief Compare Virgil CRL elements for equality
             *
             * @return true if given objects are equal, false - otherwise
             */
            inline bool operator==(const CRLElementModel& left, const CRLElementModel& right) {
                return left.getId() == right.getId()
                && left.getRevokedAt() == right.getRevokedAt()
                && left.getIdentity() == right.getIdentity();
            }
            /**
             * @brief CompareRL elements for inequality
             *
             * @return true if given objects are inequal, false - otherwise
             */
            inline bool operator!=(const CRLElementModel& left, const CRLElementModel& right) {
                return !(left == right);
            }
        }
    }
}

#endif /* VIRGIL_SDK_MODELS_CRL_ELEMENT_MODEL_H */
