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

#include <virgil/sdk/cards/verification/VirgilCardVerifier.h>

using virgil::sdk::cards::verification::VirgilCardVerifier;
using virgil::sdk::cards::Card;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::crypto::keys::PublicKey;
using virgil::sdk::VirgilByteArrayUtils;

const std::string VirgilCardVerifier::selfSignerIdentifier = "self";
const std::string VirgilCardVerifier::virgilSignerIdentifier = "virgil";
const std::string VirgilCardVerifier::virgilPublicKeyBase64 = "MCowBQYDK2VwAyEAljOYGANYiVq1WbvVvoYIKtvZi2ji9bAhxyu6iV/LF8M=";

VirgilCardVerifier::VirgilCardVerifier(const Crypto &crypto, const std::vector<Whitelist> &whitelists)
: crypto_(crypto), whitelists_(whitelists), verifySelfSignature(true), verifyVirgilSignature(true),
  virgilPublicKey(crypto.importPublicKey(VirgilBase64::decode(virgilPublicKeyBase64))) {}

const Crypto& VirgilCardVerifier::crypto() const { return crypto_; }

bool VirgilCardVerifier::verifyCard(const Card &card) const {
    return verifySelf(card) && verifyVirgil(card) && verifyWhitelists(card);
}

bool VirgilCardVerifier::verifySelf(const virgil::sdk::cards::Card &card) const {
    if (verifySelfSignature)
        return verify(card, selfSignerIdentifier, card.publicKey());

    return false;
}

bool VirgilCardVerifier::verifyVirgil(const virgil::sdk::cards::Card &card) const {
    if (verifyVirgilSignature)
        return verify(card, virgilSignerIdentifier, virgilPublicKey);

    return false;
}

bool VirgilCardVerifier::verifyWhitelists(const virgil::sdk::cards::Card &card) const {
    for (const auto& whitelist : whitelists_) {
        bool result = false;
        for (auto& credentials : whitelist.verifierCredentials()) {
            for (auto &signature : card.signatures()) {
                if (signature.signer() == credentials.signer()) {
                    auto publicKey = crypto_.importPublicKey(credentials.publicKey());
                    result = verify(card, credentials.signer(), publicKey);
                }
            }
        }
        if (!result)
            return false;
    }

    return true;
}

bool VirgilCardVerifier::verify(const virgil::sdk::cards::Card &card, const std::string &signer,
                                const PublicKey &signerPublicKey) const {
    for (auto& signature : card.signatures()) {
        if (signature.signer() == signer) {
            auto cardSnapshot = card.getRawCard().contentSnapshot();
            VirgilByteArrayUtils::append(cardSnapshot, signature.snapshot());

            return crypto_.verify(cardSnapshot, signature.signature(), signerPublicKey);
        }
    }

    return false;
}