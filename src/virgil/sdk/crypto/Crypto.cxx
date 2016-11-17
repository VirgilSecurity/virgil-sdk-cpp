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

#include <virgil/sdk/crypto/Crypto.h>

#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>

#include <type_traits>

static_assert(!std::is_abstract<virgil::sdk::crypto::Crypto>(), "Crypto must not be abstract.");

using namespace virgil::sdk::crypto;
using namespace virgil::sdk::crypto::keys;

using namespace virgil::crypto;

Crypto::Crypto() {

}

KeyPair Crypto::generateKeyPair() const {
    VirgilKeyPair keyPair = VirgilKeyPair::generateRecommended();

    VirgilByteArray keyPairId = computeHashForPublicKey(keyPair.publicKey());

    PrivateKey privateKey = PrivateKey(keyPair.privateKey(), keyPairId);
    PublicKey publicKey = PublicKey(keyPair.publicKey(), keyPairId);

    return KeyPair(std::move(privateKey), std::move(publicKey));
}

PrivateKey Crypto::importPrivateKey(const VirgilByteArray &data, const std::string &password) const {
    // FIXME
    VirgilByteArray privateKeyData = password.length() == 0 ? VirgilKeyPair::privateKeyToDER(data) : VirgilKeyPair::decryptPrivateKey(data, VirgilByteArrayUtils::stringToBytes(password));

    VirgilByteArray publicKey = VirgilKeyPair::extractPublicKey(privateKeyData, VirgilByteArray());

    VirgilByteArray keyIdentifier = computeHashForPublicKey(publicKey);

    VirgilByteArray exportedPrivateKeyData = VirgilKeyPair::privateKeyToDER(privateKeyData);

    return PrivateKey(std::move(exportedPrivateKeyData), std::move(keyIdentifier));
}

PublicKey Crypto::importPublicKey(const VirgilByteArray &data) const {
    VirgilByteArray keyIdentifier = computeHashForPublicKey(data);

    VirgilByteArray exportedPublicKey = VirgilKeyPair::publicKeyToDER(data);

    return PublicKey(std::move(exportedPublicKey), std::move(keyIdentifier));
}

VirgilByteArray Crypto::computeHashForPublicKey(const VirgilByteArray &publicKey) const {
    VirgilByteArray publicKeyDER = VirgilKeyPair::publicKeyToDER(publicKey);

    foundation::VirgilHash hash = foundation::VirgilHash(foundation::VirgilHash::Algorithm::SHA256);
    return hash.hash(publicKeyDER);
}
