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

#include <virgil/sdk/client/models/responses/CardResponse.h>

using virgil::sdk::client::models::responses::CardResponse;
using virgil::sdk::client::models::Card;
using virgil::sdk::client::models::snapshotmodels::CreateCardSnapshotModel;

Card CardResponse::buildCard() const {
    return Card(identifier_, model_.identity(), model_.identityType(), model_.publicKeyData(), model_.data(),
                model_.scope(), model_.info(), createdAt_, cardVersion_);
}

CardResponse::CardResponse(
        std::unordered_map<std::string, VirgilByteArray> signatures,
        VirgilByteArray snapshot,
        CreateCardSnapshotModel model,
        std::string identifier,
        std::string createdAt,
        std::string cardVersion)
        : signatures_(std::move(signatures)), snapshot_(std::move(snapshot)),
          model_(std::move(model)), identifier_(std::move(identifier)),
          createdAt_(std::move(createdAt)), cardVersion_(std::move(cardVersion)) {
}
