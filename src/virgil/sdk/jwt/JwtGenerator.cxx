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

#include <virgil/sdk/jwt/JwtGenerator.h>

using virgil::sdk::jwt::JwtGenerator;
using virgil::sdk::jwt::Jwt;
using virgil::sdk::jwt::JwtHeaderContent;
using virgil::sdk::jwt::JwtBodyContent;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::crypto::keys::PrivateKey;

JwtGenerator::JwtGenerator(PrivateKey apiKey, std::string apiPublicKeyIdentifier,
                           std::shared_ptr<Crypto> crypto, std::string appId, int ttl)
: apiKey_(std::move(apiKey)), apiPublicKeyIdentifier_(std::move(apiPublicKeyIdentifier)),
  crypto_(std::move(crypto)), appId_(std::move(appId)), ttl_(ttl) {}

Jwt JwtGenerator::generateToken(const std::string &identity,
                                const std::unordered_map<std::string, std::string> &additionalData) const {
    auto headerContent = JwtHeaderContent(apiPublicKeyIdentifier_);
    auto bodyContent = JwtBodyContent(appId_, identity, std::time(0) + ttl_, std::time(0), additionalData);
    auto data = Jwt::dataToSign(headerContent, bodyContent);
    auto signatureContent = crypto_->generateSignature(data, apiKey_);

    return Jwt(headerContent, bodyContent, signatureContent);
}

const PrivateKey& JwtGenerator::apiKey() const { return apiKey_; }

const std::string& JwtGenerator::apiPublicKeyIdentifier() const { return apiPublicKeyIdentifier_; }

const std::shared_ptr<Crypto>& JwtGenerator::crypto() const { return crypto_; }

const std::string& JwtGenerator::appId() const { return appId_; }

int JwtGenerator::ttl() const { return ttl_; }
