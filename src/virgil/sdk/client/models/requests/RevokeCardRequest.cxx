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

#include <virgil/sdk/client/models/requests/RevokeCardRequest.h>
#include <virgil/sdk/client/models/serialization/CanonicalSerializer.h>

static_assert(!std::is_abstract<virgil::sdk::client::models::requests::RevokeCardRequest>(), "RevokeCardRequest must not be abstract.");

using virgil::sdk::client::models::requests::RevokeCardRequest;
using virgil::sdk::client::models::requests::SignableRequest;
using virgil::sdk::client::models::snapshotmodels::RevokeCardSnapshotModel;
using virgil::sdk::client::models::serialization::CanonicalSerializer;

RevokeCardRequest RevokeCardRequest::createRequest(const std::string &cardId, CardRevocationReason reason) {
    return RevokeCardRequest(cardId, reason);
}

RevokeCardRequest::RevokeCardRequest(const std::string &cardId, CardRevocationReason reason)
        : RevokeCardRequest(
            RevokeCardSnapshotModel::createModel(cardId, reason)) {
}

RevokeCardRequest::RevokeCardRequest(
        const VirgilByteArray &snapshot,
        const std::unordered_map<std::string, VirgilByteArray> &signatures)
        : SignableRequest<RevokeCardSnapshotModel, RevokeCardRequest>(
            snapshot,
            CanonicalSerializer<RevokeCardSnapshotModel>::fromCanonicalForm(snapshot),
            signatures) {
}

RevokeCardRequest::RevokeCardRequest(
        const snapshotmodels::RevokeCardSnapshotModel &model,
        const std::unordered_map<std::string, VirgilByteArray> &signatures)
        : SignableRequest<RevokeCardSnapshotModel, RevokeCardRequest>(model) {
}

