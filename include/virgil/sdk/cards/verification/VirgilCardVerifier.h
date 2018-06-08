/**
 * Copyright (C) 2018 Virgil Security Inc.
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
                class VirgilCardVerifier : public CardVerifierInterface {
                public:
                    VirgilCardVerifier(const std::shared_ptr<crypto::Crypto>& crypto,
                                       const std::vector<Whitelist>& whitelists = std::vector<Whitelist>());

                    static const std::string selfSignerIdentifier_;
                    static const std::string virgilSignerIdentifier_;
                    static const std::string virgilPublicKeyBase64_;

                    const std::shared_ptr<crypto::Crypto>& crypto() const;

                    const crypto::keys::PublicKey virgilPublicKey() const;

                    const std::vector<Whitelist>& whitelists() const;
                    void whitelists(const std::vector<Whitelist>& newWhitelists);

                    bool verifyCard(const Card &card) const override;

                    const bool verifySelfSignature() const;
                    void verifySelfSignature(const bool& newVerifySelfSignature);

                    const bool verifyVirgilSignature() const;
                    void verifyVirgilSignature(const bool& newVerifyVirgilSignature);

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