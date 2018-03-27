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

#include <virgil/sdk/client/models/RawSignedModel.h>
#include <virgil/sdk/client/models/serialization/JsonDeserializer.h>
#include <virgil/sdk/client/models/serialization/JsonSerializer.h>

using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::client::models::RawSignature;
using virgil::sdk::VirgilByteArray;
using virgil::sdk::client::models::serialization::JsonDeserializer;
using virgil::sdk::client::models::serialization::JsonSerializer;

RawSignedModel::RawSignedModel(const VirgilByteArray &contentSnapshot)
: contentSnapshot_(contentSnapshot) {
    signatures_ = std::vector<RawSignature>();
}

void RawSignedModel::addSignature(const RawSignature &newSignature) {
    for (RawSignature& signature : signatures_) {
        if (signature.signer() == newSignature.signer())
            //FIXME: throw error
            return;
    }
    signatures_.push_back(newSignature);
}

std::string RawSignedModel::exportAsJson() const {
    return JsonSerializer<RawSignedModel>::toJson(*this);
}

std::string RawSignedModel::exportAsBase64EncodedString() const {
    return VirgilBase64::encode(VirgilByteArrayUtils::stringToBytes(this->exportAsJson()));
}

RawSignedModel RawSignedModel::importFromJson(const std::string &data) {
    return JsonDeserializer<RawSignedModel>::fromJsonString(data);
}

RawSignedModel RawSignedModel::importFromBase64EncodedString(const std::string &data) {
    auto decodedStr = VirgilByteArrayUtils::bytesToString(VirgilBase64::decode(data));
    return JsonDeserializer<RawSignedModel>::fromJsonString(decodedStr);
}

const VirgilByteArray& RawSignedModel::contentSnapshot() const { return contentSnapshot_; }

const std::vector<RawSignature> RawSignedModel::signatures() const { return signatures_; }