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

#include <virgil/sdk/VirgilUri.h>

using virgil::sdk::VirgilUri;

using virgil::sdk::endpoints::IdentityEndpointUri;
using virgil::sdk::endpoints::PublicKeysEndpointUri;
using virgil::sdk::endpoints::PrivateKeysEndpointUri;

const std::string VirgilUri::kIdentityServiceUri = "https://identity-stg.virgilsecurity.com";
const std::string VirgilUri::kPublicKeyServiceUri = "https://keys-stg.virgilsecurity.com";
const std::string VirgilUri::kPrivateKeyServiceUri = "https://keys-private-stg.virgilsecurity.com";

// const std::string VirgilUri::kIdentityServiceUri = "https://identity.virgilsecurity.com";
// const std::string VirgilUri::kPublicKeyServiceUri = "https://keys.virgilsecurity.com";
// const std::string VirgilUri::kPrivateKeyServiceUri = "https://private-keys.virgilsecurity.com";


VirgilUri::VirgilUri()
    : identityService_(kIdentityServiceUri),
      publicKeyService_(kPublicKeyServiceUri),
      privateKeyService_(kPrivateKeyServiceUri) {

}

VirgilUri::VirgilUri(const std::string& identityService, const std::string& publicKeyService,
        const std::string& privateKeyService)
    : identityService_(identityService),
      publicKeyService_(publicKeyService),
      privateKeyService_(privateKeyService) {

}

std::string VirgilUri::getIdentityService() const {
    return identityService_;
}

std::string VirgilUri::getPublicKeyService() const {
    return publicKeyService_;
}

std::string VirgilUri::getPrivateKeyService() const {
    return privateKeyService_;
}

void VirgilUri::setIdentityService(const std::string& uri) {
    identityService_ = uri;
}

void VirgilUri::setPublicKeyService(const std::string& uri) {
    publicKeyService_ = uri;
}

void VirgilUri::setPrivateKeyService(const std::string& uri) {
    privateKeyService_ = uri;
}

