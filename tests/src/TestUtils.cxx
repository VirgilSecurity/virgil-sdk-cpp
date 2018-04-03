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


#include <TestUtils.h>
#include <helpers.h>
#include <virgil/sdk/jwt/JwtGenerator.h>
#include <virgil/sdk/jwt/providers/GeneratorJwtProvider.h>

using virgil::sdk::VirgilByteArrayUtils;
using virgil::sdk::test::Utils;
using virgil::sdk::test::TestUtils;
using virgil::sdk::jwt::Jwt;
using virgil::sdk::jwt::JwtGenerator;
using virgil::sdk::jwt::providers::GeneratorJwtProvider;
using virgil::sdk::jwt::TokenContext;
using virgil::sdk::cards::Card;

Jwt TestUtils::getToken(const std::string &identity) {
    auto privateKeyData = VirgilBase64::decode(consts.ApiPrivateKey());
    auto privateKey = crypto_->importPrivateKey(privateKeyData);

    auto jwtGenerator = JwtGenerator(privateKey, consts.ApiPublicKeyId(), *crypto_, consts.AppId(), 1000);

    return jwtGenerator.generateToken(identity);
}

bool TestUtils::isCardsEqual(const Card &card1, const Card &card2) {
    auto equals = card1.identifier() == card2.identifier()
                  && card1.identity() == card2.identity()
                  && card1.version() == card2.version()
                  && card1.createdAt() == card2.createdAt()
                  && card1.previousCardId() == card2.previousCardId()
                  && card1.isOutdated() == card2.isOutdated()
                  && card1.contentSnapshot() == card2.contentSnapshot()
                  && ((card1.previousCard() == nullptr && card2.previousCard() == nullptr) || (isCardsEqual(*card1.previousCard(), *card2.previousCard())));

    return equals;
}

const std::shared_ptr<Crypto>& TestUtils::crypto() const { return crypto_; }