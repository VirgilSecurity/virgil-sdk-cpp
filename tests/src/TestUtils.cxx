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
#include <random>

using virgil::sdk::VirgilByteArrayUtils;
using virgil::sdk::test::Utils;
using virgil::sdk::test::TestUtils;
using virgil::sdk::jwt::Jwt;
using virgil::sdk::jwt::JwtGenerator;
using virgil::sdk::jwt::providers::GeneratorJwtProvider;
using virgil::sdk::jwt::TokenContext;
using virgil::sdk::cards::Card;
using virgil::sdk::client::models::RawCardContent;
using virgil::sdk::client::models::RawSignature;
using virgil::sdk::cards::CardSignature;
using virgil::sdk::VirgilByteArray;

Jwt TestUtils::getToken(const std::string &identity, const int& ttl) const {
    auto privateKeyData = VirgilBase64::decode(consts.ApiPrivateKey());
    auto privateKey = crypto_->importPrivateKey(privateKeyData);

    auto jwtGenerator = JwtGenerator(privateKey, consts.ApiPublicKeyId(), *crypto_, consts.AppId(), ttl);

    return jwtGenerator.generateToken(identity);
}

bool TestUtils::isCardsEqual(const Card &card1, const Card &card2) const {
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

bool TestUtils::isRawCardContentEqual(const RawCardContent &content1, const RawCardContent &content2) const {
    auto equals = content1.identity() == content2.identity()
                  && content1.publicKey() == content2.publicKey()
                  && content1.version() == content2.version()
                  && content1.createdAt() == content2.createdAt()
                  && content1.previousCardId() == content2.previousCardId();

    return equals;
}

bool TestUtils::isRawSignaturesEqual(const std::vector<RawSignature> &signatures1,
                                                   const std::vector<RawSignature> &signatures2) const {
    if (signatures1.size() != signatures2.size())
        return false;

    for (auto& signature1 : signatures1) {
        bool found = false;
        for (auto &signature2 : signatures2) {
            if (signature1.signer() == signature2.signer()) {
                found = true;
                if (signature1.signature() != signature2.signature() || signature1.snapshot() != signature2.snapshot())
                    return false;
            }
        }
        if (!found)
            return false;
    }

    return true;
}

bool TestUtils::isCardSignaturesEqual(const std::vector<CardSignature> &signatures1,
                                      const std::vector<CardSignature> &signatures2) const {
    if (signatures1.size() != signatures2.size())
        return false;

    for (auto& signature1 : signatures1) {
        bool found = false;
        for (auto &signature2 : signatures2) {
            if (signature1.signer() == signature2.signer()) {
                found = true;
                if (signature1.signature() != signature2.signature()
                    || signature1.snapshot() != signature2.snapshot()
                    || signature1.extraFields() != signature2.extraFields())
                    return false;
            }
        }
        if (!found)
            return false;
    }

    return true;
}

VirgilByteArray TestUtils::getRandomBytes(const int& size) const {
    std::independent_bits_engine<std::default_random_engine, CHAR_BIT, unsigned char> engine;
    VirgilByteArray data(size);
    std::generate(begin(data), end(data), std::ref(engine));

    return data;
}

std::string TestUtils::getRandomString(const int &size) const {
    srand(time(0));
    static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";

    std::string s;
    for (int i = 0; i < size; ++i) {
        s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    return s;
}

const std::shared_ptr<Crypto>& TestUtils::crypto() const { return crypto_; }