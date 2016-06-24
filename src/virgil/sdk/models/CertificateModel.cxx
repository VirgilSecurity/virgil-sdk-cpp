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

#include <virgil/sdk/models/CertificateModel.h>
#include <virgil/sdk/models/CardModel.h>
#include <virgil/sdk/io/Marshaller.h>

#include <virgil/crypto/foundation/VirgilBase64.h>
#include <virgil/crypto/VirgilSigner.h>

using virgil::sdk::models::CertificateModel;
using virgil::sdk::io::Marshaller;
using virgil::sdk::models::CardModel;
using virgil::crypto::VirgilSigner;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilBase64;

CertificateModel::CertificateModel(const virgil::sdk::models::CardModel & card,
                                   const std::string & signId,
                                   const virgil::crypto::VirgilByteArray & sign) :
card_(card),
signId_(signId),
sign_(sign) {
}

CertificateModel::CertificateModel(const std::string & cardStr,
                                   const std::string & signId,
                                   const virgil::crypto::VirgilByteArray & sign) :
originalCardStr_(cardStr),
signId_(signId),
sign_(sign) {
    card_ = Marshaller<CardModel>::fromJson(originalCardStr_);
}

const virgil::sdk::models::CardModel CertificateModel::getCard() const {
    return card_;
}

const std::string CertificateModel::getOrignalCard() const {
    return originalCardStr_;
}

const std::string CertificateModel::getSignId() const {
    return signId_;
}

const virgil::crypto::VirgilByteArray CertificateModel::getSign() const {
    return sign_;
}

bool CertificateModel::verifyWith(const CertificateModel & checkerCertificate) const {
    const std::string toBeVerified(signId_ + originalCardStr_);
    
    return VirgilSigner().verify(virgil::crypto::str2bytes(toBeVerified),
                                 sign_,
                                 checkerCertificate.getCard().getPublicKey().getKey());
}
