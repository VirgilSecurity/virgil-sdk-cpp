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

#include <virgil/sdk/jwt/providers/GeneratorJwtProvider.h>

using virgil::sdk::jwt::providers::GeneratorJwtProvider;
using virgil::sdk::jwt::interfaces::AccessTokenInterface;
using virgil::sdk::jwt::JwtGenerator;

GeneratorJwtProvider::GeneratorJwtProvider(const virgil::sdk::jwt::JwtGenerator &jwtGenerator,
                                           const std::string &defaultIdentity,
                                           const std::unordered_map<std::string, std::string> &additionalData)
: jwtGenerator_(jwtGenerator), defaultIdentity_(defaultIdentity), additionalData_(additionalData) {}

std::future<std::shared_ptr<AccessTokenInterface>> GeneratorJwtProvider::getToken(
        const virgil::sdk::jwt::TokenContext &tokenContext)
{
    auto identity = tokenContext.identity().empty() ? defaultIdentity_ : tokenContext.identity();
    auto token = jwtGenerator_.generateToken(identity, additionalData_);

    std::promise<std::shared_ptr<AccessTokenInterface>> p;
    p.set_value(std::make_shared<Jwt>(token));

    return p.get_future();
}

const JwtGenerator& GeneratorJwtProvider::jwtGenerator() const { return jwtGenerator_; }

const std::string& GeneratorJwtProvider::defaultIdentity() const { return defaultIdentity_; }

const std::unordered_map<std::string, std::string>& GeneratorJwtProvider::additionalData() const { return additionalData_; }