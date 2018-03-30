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

#include <virgil/sdk/jwt/JwtHeaderContent.h>
#include <virgil/sdk/util/Base64Url.h>
#include <virgil/sdk/serialization/JsonSerializer.h>
#include <virgil/sdk/serialization/JsonDeserializer.h>

using virgil::sdk::jwt::JwtHeaderContent;
using virgil::sdk::util::Base64Url;
using virgil::sdk::serialization::JsonSerializer;
using virgil::sdk::serialization::JsonDeserializer;

JwtHeaderContent::JwtHeaderContent(const std::string &keyIdentifier, const std::string &algorithm,
                                   const std::string &type, const std::string &contentType)
: keyIdentifier_(keyIdentifier), algorithm_(algorithm), type_(type), contentType_(contentType) {}

JwtHeaderContent JwtHeaderContent::parse(const std::string &base64url) {
    return JsonDeserializer<JwtHeaderContent>::fromJsonString(Base64Url::decode(base64url));
}

std::string JwtHeaderContent::base64Url() const {
    return Base64Url::encode(JsonSerializer<JwtHeaderContent>::toJson(*this));
}

const std::string& JwtHeaderContent::algorithm() const { return algorithm_; }

const std::string& JwtHeaderContent::type() const { return type_; }

const std::string& JwtHeaderContent::contentType() const { return contentType_; }

const std::string& JwtHeaderContent::keyIdentifier() const { return keyIdentifier_; }