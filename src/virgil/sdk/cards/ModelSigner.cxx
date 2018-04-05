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

#include <virgil/sdk/cards/ModelSigner.h>
#include <virgil/sdk/client/models/RawSignature.h>
#include <virgil/sdk/util/JsonUtils.h>

using virgil::sdk::cards::ModelSigner;
using virgil::sdk::VirgilByteArray;
using virgil::sdk::VirgilByteArrayUtils;
using virgil::sdk::client::models::RawSignedModel;
using virgil::sdk::client::models::RawSignature;
using virgil::sdk::crypto::keys::PrivateKey;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::util::JsonUtils;

ModelSigner::ModelSigner(const Crypto &crypto)
        : crypto_(crypto) {}

const std::string ModelSigner::selfSignerIdentifier = "self";

const Crypto& ModelSigner::crypto() const { return crypto_; }

void ModelSigner::sign(RawSignedModel &model, const std::string &signer,
                       const PrivateKey &privateKey) const {
    this->sign(model, signer, privateKey, VirgilByteArray());
}

void ModelSigner::sign(RawSignedModel &model,
                       const std::string &signer,
                       const PrivateKey &privateKey,
                       const VirgilByteArray &additionalData) const {
    auto combinedSnapshot = model.contentSnapshot();
    VirgilByteArrayUtils::append(combinedSnapshot, additionalData);

    auto signature = crypto_.generateSignature(combinedSnapshot, privateKey);
    auto rawSignature = RawSignature(signer, signature, additionalData);

    model.addSignature(rawSignature);
}

void ModelSigner::selfSign(virgil::sdk::client::models::RawSignedModel &model,
                           const virgil::sdk::crypto::keys::PrivateKey &privateKey) const {
    this->sign(model, selfSignerIdentifier, privateKey, VirgilByteArray());
}

void ModelSigner::selfSign(virgil::sdk::client::models::RawSignedModel &model,
                           const virgil::sdk::crypto::keys::PrivateKey &privateKey,
                           const virgil::sdk::VirgilByteArray &additionalData) const {
    this->sign(model, selfSignerIdentifier, privateKey, additionalData);
}

void ModelSigner::sign(virgil::sdk::client::models::RawSignedModel &model, const std::string &signer,
                       const virgil::sdk::crypto::keys::PrivateKey &privateKey,
                       const std::unordered_map<std::string, std::string> &extraFields) const {
    auto additionalData = VirgilByteArray();
    if (!extraFields.empty()) {
        auto extraFieldsStr = JsonUtils::unorderedMapToJson(extraFields).dump();
        additionalData = VirgilByteArrayUtils::stringToBytes(extraFieldsStr);
    }

    this->sign(model, signer, privateKey, additionalData);
}

void ModelSigner::selfSign(virgil::sdk::client::models::RawSignedModel &model,
                           const virgil::sdk::crypto::keys::PrivateKey &privateKey,
                           const std::unordered_map<std::string, std::string> &extraFields) const {
    auto additionalData = VirgilByteArray();
    if (!extraFields.empty()) {
        auto extraFieldsStr = JsonUtils::unorderedMapToJson(extraFields).dump();
        additionalData = VirgilByteArrayUtils::stringToBytes(extraFieldsStr);
    }

    this->selfSign(model, privateKey, additionalData);
}