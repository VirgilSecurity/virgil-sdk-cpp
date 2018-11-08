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

#ifndef VIRGIL_SDK_VIRGILCARDVERIFIER_H
#define VIRGIL_SDK_VIRGILCARDVERIFIER_H

#include <vector>
#include <memory>
#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/sdk/cards/verification/Whitelist.h>
#include <virgil/sdk/cards/verification/CardVerifierInterface.h>

namespace virgil {
    namespace sdk {
        namespace cards {
            namespace verification {
                /*!
                 * @brief Virgil implementation of CardVerifierInterface
                 * @note By default verifies Card's self signature and Virgil Cards Service signature
                 */
                class VirgilCardVerifier : public CardVerifierInterface {
                public:
                    /*!
                     * @brief Constructor
                     * @param crypto std::shared_ptr to Crypto instance
                     * @param whitelists std::vector with collections of verifiers
                     * @param verifySelfSignature VirgilCardVerifier will verify self signature if true
                     * @param verifyVirgilSignature VirgilCardVerifier will verify Virgil Cards Service signature if true
                     * @note VirgilCardVerifier verifies Card if it contains signature from AT LEAST
                     * one verifier from EACH Whitelist
                     */
                    VirgilCardVerifier(std::shared_ptr<crypto::Crypto> crypto,
                                       std::vector<Whitelist> whitelists = std::vector<Whitelist>(),
                                       bool verifySelfSignature = true,
                                       bool verifyVirgilSignature = true);

                    /*!
                     * @brief Signer identifier for self signatures
                     */
                    static const std::string selfSignerIdentifier_;

                    /*!
                     * @brief Signer identifier for Virgil Cards Service signature
                     */
                    static const std::string virgilSignerIdentifier_;

                    /*!
                     * @brief Base64 encoded string with Virgil Service's Public Key for verifying Virgil Cards Service signature
                     */
                    static const std::string virgilPublicKeyBase64_;

                    /*!
                     * @brief Getter
                     * @return std::shared_ptr to Crypto instance
                     */
                    const std::shared_ptr<crypto::Crypto>& crypto() const;

                    /*!
                     * @brief Getter
                     * @return Public Key of Virgil Cards Service
                     */
                    const crypto::keys::PublicKey virgilPublicKey() const;

                    /*!
                     * @brief Getter
                     * @return std::vector with collections of verifiers
                     */
                    const std::vector<Whitelist>& whitelists() const;

                    /*!
                     * @brief Getter
                     * @return true if VirgilCardVerifier will verify self signature, false otherwise
                     */
                    bool verifySelfSignature() const;

                    /*!
                     * Getter
                     * @return true if VirgilCardVerifier will verify Virgil Cards Service signature, false otherwise
                     */
                    bool verifyVirgilSignature() const;

                    /*!
                     * @brief Verifies Card instance using set rules
                     * @param card Card to verify
                     * @return true if Card verified, false otherwise
                     * @note VirgilCardVerifier verifies Card if it contains signature from AT LEAST
                     * one verifier from EACH Whitelist
                     */
                    bool verifyCard(const Card &card) const override;

                private:
                    bool verifySelfSignature_;
                    bool verifyVirgilSignature_;
                    crypto::keys::PublicKey virgilPublicKey_;
                    std::shared_ptr<crypto::Crypto> crypto_;
                    std::vector<Whitelist> whitelists_;

                    bool verifySelf(const Card &card) const;
                    bool verifyVirgil(const Card &card) const;
                    bool verifyWhitelists(const Card &card) const;
                    bool verify(const Card &card, const std::string& signer,
                                const crypto::keys::PublicKey& signerPublicKey) const;
                };
            }
        }
    }
}

#endif //VIRGIL_SDK_VIRGILCARDVERIFIER_H