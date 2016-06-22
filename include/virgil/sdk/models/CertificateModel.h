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

#ifndef VIRGIL_SDK_MODELS_CERTIFICATE_MODEL_H
#define VIRGIL_SDK_MODELS_CERTIFICATE_MODEL_H

#include <string>
#include <map>

#include <virgil/sdk/models/CardModel.h>

namespace virgil {
namespace sdk {
    namespace models {
        /**
         * @brief Data object represent "Virgil Certificate" entity
         */
        class CertificateModel {
        public:
            /**
             * @brief Create empty non valid Virgil Certificate
             */
            CertificateModel() = default;
            /**
             * @brief Create Virgil Certificate with all associated data
             *
             * @param card - Virgil Card
             * @param signId - signature id
             * @param sign - signature of the certificate
             */
            CertificateModel(const virgil::sdk::models::CardModel & card,
                             const std::string & signId,
                             const virgil::crypto::VirgilByteArray & sign);
            /**
             * @brief Return Virgil Card
             */
            const virgil::sdk::models::CardModel getCard() const;
            /**
             * @brief Return signature id
             */
            const std::string getSignId() const;
            /**
             * @brief Return signature of the certificate
             */
            const virgil::crypto::VirgilByteArray getSign() const;
            
        private:
            virgil::sdk::models::CardModel card_;
            std::string signId_;
            virgil::crypto::VirgilByteArray sign_;
        };
        /**
         * @brief Compare Virgil Certificates for equality
         *
         * @return true if given objects are equal, false - otherwise
         */
        inline bool operator==(const CertificateModel & left, const CertificateModel & right) {
            return left.getCard() == right.getCard() &&
                   left.getSignId() == right.getSignId() &&
                   left.getSign() == right.getSign();
        }
        /**
         * @brief Compare Virgil Certificates for inequality
         *
         * @return true if given objects are inequal, false - otherwise
         */
        inline bool operator!=(const CertificateModel & left, const CertificateModel & right) {
            return !(left == right);
        }
    }
}
}

#endif /* VIRGIL_SDK_MODELS_CERTIFICATE_MODEL_H */
