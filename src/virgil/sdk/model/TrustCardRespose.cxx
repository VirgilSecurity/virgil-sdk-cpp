/**
 * Copyright (C) 2015 Virgil Security Inc.
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

#include <virgil/sdk/model/TrustCardResponse.h>

using virgil::sdk::model::TrustCardResponse;


TrustCardResponse::TrustCardResponse(
		const std::string& id,
        const std::string& createdAt,
        const std::string& signerVirgilCardId,
        const std::string& signedVirgilCardId,
        const std::string& signedDigest) 
        	: id_(id),
        	  createdAt_(createdAt),
        	  signerVirgilCardId_(signerVirgilCardId),
        	  signedVirgilCardId_(signedVirgilCardId),
        	  signedDigest_(signedDigest) {

}

std::string TrustCardResponse::getId() const {
	return id_;
}

std::string TrustCardResponse::getCreatedAt() const {
	return createdAt_;
}

std::string TrustCardResponse::getSignerVirgilCardId() const {
	return signerVirgilCardId_;
}

std::string TrustCardResponse::getSignedVirgilCardId() const {
	return signedVirgilCardId_;
}

std::string TrustCardResponse::getSignedDigest() const {
	return signedDigest_;
}

void TrustCardResponse::setId(const std::string& id) {
	id_ = id;
}

void TrustCardResponse::setCreatedAt(const std::string& createdAt) {
	createdAt_ = createdAt;
}

void TrustCardResponse::setSignerVirgilCardId(const std::string& signerVirgilCardId) {
	signerVirgilCardId_ = signerVirgilCardId;
}

void TrustCardResponse::setSignedVirgilCardId(const std::string& signedVirgilCardId) {
	signedVirgilCardId_ = signedVirgilCardId;
}

void TrustCardResponse::setSignedDigest(const std::string& signedDigest) {
	signedDigest_ = signedDigest;
}
