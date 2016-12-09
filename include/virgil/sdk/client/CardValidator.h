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

#ifndef VIRGIL_SDK_CARDVALIDATOR_H
#define VIRGIL_SDK_CARDVALIDATOR_H

#include <virgil/sdk/crypto/CryptoInterface.h>
#include <virgil/sdk/crypto/keys/PublicKey.h>
#include <virgil/sdk/client/interfaces/CardValidatorInterface.h>

namespace virgil {
namespace sdk {
namespace client {
    /*!
     * @brief Default implementation of CardValidatorInterface
     */
    class CardValidator: public interfaces::CardValidatorInterface {
    public:
        /*!
         * @brief Constructor.
         * @param crypto std::shared_ptr to some CryptoInterface implementation
         */
        CardValidator(const std::shared_ptr<crypto::CryptoInterface> &crypto);

        /*!
         * @brief Adds custom verifier to validator.
         * @param verifierId std::string verifier ID
         * @param publicKeyData exported Public Key of verifier
         */
        void addVerifier(std::string verifierId, VirgilByteArray publicKeyData);

        /*!
         * @brief Getter.
         * @return std::unordered_map of all verifiers, except owner
         */
        const std::unordered_map<std::string, VirgilByteArray>& verifiers() const { return verifiers_; };

        /// @section CardValidatorInterface implementation
        bool validateCardResponse(const models::responses::CardResponse &response) const override;

    private:
        std::shared_ptr<crypto::CryptoInterface> crypto_;
        std::unordered_map<std::string, VirgilByteArray> verifiers_;
    };
}
}
}

#endif //VIRGIL_SDK_CARDVALIDATOR_H
