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

#include <sstream>
#include <virgil/sdk/jwt/Jwt.h>
#include <virgil/sdk/util/Base64Url.h>

using virgil::sdk::jwt::Jwt;
using virgil::sdk::jwt::JwtHeaderContent;
using virgil::sdk::jwt::JwtBodyContent;
using virgil::sdk::VirgilByteArray;
using virgil::sdk::VirgilByteArrayUtils;
using virgil::sdk::util::Base64Url;

Jwt::Jwt(JwtHeaderContent headerContent, JwtBodyContent bodyContent, VirgilByteArray signatureContent)
        : headerContent_(std::move(headerContent)), bodyContent_(std::move(bodyContent)),
          signatureContent_(std::move(signatureContent)) {
    dataToSign_ = Jwt::dataToSign(headerContent_, bodyContent_);
    stringRepresentation_ = headerContent_.base64Url() + "." + bodyContent_.base64Url() + "." + signatureBase64Url();
}

Jwt Jwt::parse(const std::string &stringRepresentation) {
    std::stringstream ss(stringRepresentation);
    std::string item;
    std::vector<std::string> parts;
    while (std::getline(ss, item, '.'))
        parts.push_back(item);

    auto headerContent = JwtHeaderContent::parse(parts[0]);
    auto bodyContent = JwtBodyContent::parse(parts[1]);
    auto signatureContent = VirgilByteArrayUtils::stringToBytes(Base64Url::decode(parts[2]));

    return Jwt(headerContent, bodyContent, signatureContent);
}

VirgilByteArray Jwt::dataToSign(const virgil::sdk::jwt::JwtHeaderContent &headerContent,
                                const virgil::sdk::jwt::JwtBodyContent &bodyContent) {
    return VirgilByteArrayUtils::stringToBytes(headerContent.base64Url() + "." + bodyContent.base64Url());
}

const std::string& Jwt::identity() const {
    return bodyContent_.identity();
}

bool Jwt::isExpired() const {
    return std::time(0) >= bodyContent_.expiresAt();
}

const std::string Jwt::signatureBase64Url() const {
    return Base64Url::encode(VirgilByteArrayUtils::bytesToString(signatureContent_));
}

const JwtHeaderContent& Jwt::headerContent() const { return headerContent_; }

const JwtBodyContent& Jwt::bodyContent() const { return bodyContent_; }

const VirgilByteArray& Jwt::signatureContent() const { return signatureContent_; }

const std::string& Jwt::stringRepresentation() const { return stringRepresentation_; }

const VirgilByteArray& Jwt::dataToSign() const { return dataToSign_; }