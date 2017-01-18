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
#include <virgil/sdk/client/models/responses/CardResponse.h>
#include <virgil/sdk/client/models/serialization/JsonDeserializer.h>

using virgil::sdk::VirgilByteArrayUtils;
using virgil::sdk::client::models::CardRevocationReason;
using virgil::sdk::test::Utils;
using virgil::sdk::test::TestUtils;
using virgil::sdk::VirgilBase64;
using virgil::sdk::client::RequestSigner;
using virgil::sdk::client::models::responses::CardResponse;
using virgil::sdk::client::models::serialization::JsonDeserializer;

CreateCardRequest TestUtils::instantiateCreateCardRequest(
        const std::unordered_map<std::string, std::string> &data,
        const std::string &device,
        const std::string &deviceName) const {
    auto keyPair = crypto_->generateKeyPair();
    auto exportedPublicKey = crypto_->exportPublicKey(keyPair.publicKey());

    auto identity = Utils::generateRandomStr(40);
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

Card TestUtils::instantiateCard() const {
    auto cardResponse = JsonDeserializer<CardResponse>::fromJsonString("{\"id\":\"5bbe7efe9786e0b6d8409a5ec0fc45d7b9956548e0cc2baba58e05b8934f3d1f\",\"content_snapshot\":\"eyJpZGVudGl0eSI6IkMzN2dFRnY0RG14d25WOXRVcEJEZ2FxT3RwQ1Q0bDRSZDF0ZTJPTFEiLCJpZGVudGl0eV90eXBlIjoidGVzdCIsInB1YmxpY19rZXkiOiJNQ293QlFZREsyVndBeUVBK3c0bGNNcnBKbkN3dEExeDlHMEJTM0hzWFF5QlAxVlRTOTlUV1gzSnpOTT0iLCJzY29wZSI6ImFwcGxpY2F0aW9uIn0=\",\"meta\":{\"created_at\":\"2017-01-18T11:51:17+0000\",\"card_version\":\"4.0\",\"signs\":{\"5bbe7efe9786e0b6d8409a5ec0fc45d7b9956548e0cc2baba58e05b8934f3d1f\":\"MFEwDQYJYIZIAWUDBAICBQAEQOtH1Xxm9MAN3UJGrOjt8g6LoA5ovB2kX1IMOFgjYl7+QQy3c+Qz1qThekwS8SETTXqVEwJSvS9X+o9BDReJ4AM=\",\"c53035253366736218ea3ebc924275073aafc2e78d09fe4f910e6b33a7297dd7\":\"MFEwDQYJYIZIAWUDBAICBQAEQIATNZh6jjHvXyq314uXwzKTh9h\\/mqK3S+EeKE+pFuSoaw1BLytaN9CVyJFPkfdaRpdU2uYPMGjQlBrXfmCaDws=\",\"3e29d43373348cfb373b7eae189214dc01d7237765e572db685839b64adca853\":\"MFEwDQYJYIZIAWUDBAICBQAEQIW7qBS\\/8tHo8pKfNMb4GO1ARsWqkuh157F8JENBQSrnPhZC5oe9z8\\/2hD+OGUFoaubaDEl\\/PJcO4RzACdw46Qg=\"}}}");
    return Card::buildCard(cardResponse);
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
