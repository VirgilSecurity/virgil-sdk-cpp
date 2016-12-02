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
#include <virgil/sdk/client/models/ClientCommon.h>
#include <virgil/sdk/client/RequestSigner.h>

using virgil::sdk::VirgilByteArrayUtils;
using virgil::sdk::client::models::CardRevocationReason;
using virgil::sdk::test::Utils;
using virgil::sdk::test::TestUtils;
using virgil::sdk::VirgilBase64;
using virgil::sdk::client::RequestSigner;

CreateCardRequest TestUtils::instantiateCreateCardRequest(
        const std::unordered_map<std::string, std::string> &data,
        const std::string &device,
        const std::string &deviceName) const {
    auto keyPair = crypto_->generateKeyPair();
    auto exportedPublicKey = crypto_->exportPublicKey(keyPair.publicKey());

    auto identity = Utils::generateRandomStr(20);
    auto identityType = consts.applicationIdentityType();

    auto request = CreateCardRequest::createRequest(identity, identityType, exportedPublicKey, data, device, deviceName);

    auto privateAppKeyData = VirgilBase64::decode(consts.applicationPrivateKeyBase64());
    auto appPrivateKey = crypto_->importPrivateKey(privateAppKeyData, consts.applicationPrivateKeyPassword());

    auto signer = RequestSigner(crypto_);

    signer.selfSign(request, keyPair.privateKey());
    signer.authoritySign(request, consts.applicationId(), appPrivateKey);

    return request;
}

RevokeCardRequest TestUtils::instantiateRevokeCardRequest(const Card &card) const {
    auto request = RevokeCardRequest::createRequest(card.identifier(), CardRevocationReason::unspecified);

    auto signer = RequestSigner(crypto_);

    auto privateAppKeyData = VirgilBase64::decode(consts.applicationPrivateKeyBase64());
    auto appPrivateKey = crypto_->importPrivateKey(privateAppKeyData, consts.applicationPrivateKeyPassword());

    signer.authoritySign(request, consts.applicationId(), appPrivateKey);

    return request;
}

bool TestUtils::checkCardEquality(const Card &card, const CreateCardRequest &request) {
    auto equals = card.identityType() == request.snapshotModel().identityType()
        && card.identity() == request.snapshotModel().identity()
        && card.data() == request.snapshotModel().data()
        && card.info() == request.snapshotModel().info()
        && card.publicKeyData() == request.snapshotModel().publicKeyData()
        && card.scope() == request.snapshotModel().scope();

    return equals;
}

bool TestUtils::checkCardEquality(const Card &card1, const Card &card2) {
    auto equals = card1.identityType() == card2.identityType()
                  && card1.identity() == card2.identity()
                  && card1.identifier() == card2.identifier()
                  && card1.createdAt() == card2.createdAt()
                  && card1.cardVersion() == card2.cardVersion()
                  && card1.data() == card2.data()
                  && card1.info() == card2.info()
                  && card1.publicKeyData() == card2.publicKeyData()
                  && card1.scope() == card2.scope();

    return equals;
}

bool TestUtils::checkCreateCardRequestEquality(const CreateCardRequest &request1, const CreateCardRequest &request2) {
    auto equals = request1.snapshot() == request2.snapshot()
                  && request1.signatures() == request2.signatures()
                  && request1.snapshotModel().data() == request2.snapshotModel().data()
                  && request1.snapshotModel().identity() == request2.snapshotModel().identity()
                  && request1.snapshotModel().identityType() == request2.snapshotModel().identityType()
                  && request1.snapshotModel().info() == request2.snapshotModel().info()
                  && request1.snapshotModel().publicKeyData() == request2.snapshotModel().publicKeyData()
                  && request1.snapshotModel().scope() == request2.snapshotModel().scope();

    return equals;
}

bool TestUtils::checkRevokeCardRequestEquality(const RevokeCardRequest &request1, const RevokeCardRequest &request2) {
    auto equals = request1.snapshot() == request2.snapshot()
                  && request1.signatures() == request2.signatures()
                  && request1.snapshotModel().cardId() == request2.snapshotModel().cardId()
                  && request1.snapshotModel().revocationReason() == request2.snapshotModel().revocationReason();

    return equals;
}
