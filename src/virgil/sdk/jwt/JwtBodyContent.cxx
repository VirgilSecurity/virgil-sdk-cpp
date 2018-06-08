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

#include <virgil/sdk/jwt/JwtBodyContent.h>
#include <virgil/sdk/util/Base64Url.h>
#include <virgil/sdk/serialization/JsonSerializer.h>
#include <virgil/sdk/serialization/JsonDeserializer.h>

using virgil::sdk::jwt::JwtBodyContent;
using virgil::sdk::VirgilByteArray;
using virgil::sdk::util::Base64Url;
using virgil::sdk::serialization::JsonSerializer;
using virgil::sdk::serialization::JsonDeserializer;

JwtBodyContent::JwtBodyContent(std::string appId, std::string identity,
                               std::time_t expiresAt, std::time_t issuedAt,
                               std::unordered_map<std::string, std::string> additionalData)
: appId_(std::move(appId)), identity_(std::move(identity)), expiresAt_(expiresAt),
  issuedAt_(issuedAt), additionalData_(std::move(additionalData)) {}

JwtBodyContent JwtBodyContent::parse(const std::string &base64url) {
    return JsonDeserializer<JwtBodyContent>::fromJsonString(Base64Url::decode(base64url));
}

std::string JwtBodyContent::base64Url() const {
    return Base64Url::encode(JsonSerializer<JwtBodyContent>::toJson(*this));
}

const std::string& JwtBodyContent::appId() const { return appId_; }

const std::string& JwtBodyContent::identity() const { return identity_; }

const std::time_t& JwtBodyContent::expiresAt() const { return expiresAt_; }

const std::time_t& JwtBodyContent::issuedAt() const { return issuedAt_; }

const std::unordered_map<std::string, std::string>& JwtBodyContent::additionalData() const { return additionalData_; }