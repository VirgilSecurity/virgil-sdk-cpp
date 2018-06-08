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

#include <virgil/sdk/jwt/JwtVerifier.h>

using virgil::sdk::jwt::JwtVerifier;
using virgil::sdk::jwt::Jwt;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::crypto::keys::PublicKey;

JwtVerifier::JwtVerifier(PublicKey apiPublicKey,
                         std::string apiPublicKeyIdentifier,
                         std::shared_ptr<Crypto> crypto)
: apiPublicKey_(std::move(apiPublicKey)),
  apiPublicKeyIdentifier_(std::move(apiPublicKeyIdentifier)),
  crypto_(std::move(crypto)) {}

bool JwtVerifier::verifyToken(const Jwt &token) const {
    try {
        const auto& data = token.dataToSign();
        const auto& signature = token.signatureContent();

        return crypto_->verify(data, signature, apiPublicKey_);
    } catch (...) {
        return false;
    }
}

const PublicKey& JwtVerifier::apiPublicKey() const { return apiPublicKey_; }

const std::string& JwtVerifier::apiPublicKeyIdentifier() const { return apiPublicKeyIdentifier_; }

const std::shared_ptr<Crypto>& JwtVerifier::crypto() const { return crypto_; }