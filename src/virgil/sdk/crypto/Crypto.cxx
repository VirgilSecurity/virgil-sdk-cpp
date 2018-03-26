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
#include <virgil/sdk/crypto/Fingerprint.h>
#include <virgil/sdk/VirgilSdkError.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilCipher.h>
#include <virgil/crypto/VirgilChunkCipher.h>
#include <virgil/crypto/stream/VirgilStreamDataSink.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>
#include <virgil/crypto/VirgilSigner.h>
#include <virgil/crypto/VirgilStreamSigner.h>

static_assert(!std::is_abstract<virgil::sdk::crypto::Crypto>(), "Crypto must not be abstract.");

using virgil::sdk::make_error;
using virgil::sdk::VirgilByteArrayUtils;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::VirgilByteArray;
using virgil::sdk::VirgilByteArrayUtils;
using virgil::sdk::crypto::Fingerprint;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::VirgilSigner;
using virgil::crypto::VirgilCipher;
using virgil::crypto::VirgilChunkCipher;
using virgil::crypto::VirgilStreamSigner;
using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::stream::VirgilStreamDataSource;
using virgil::crypto::stream::VirgilStreamDataSink;
using virgil::sdk::crypto::keys::PrivateKey;
using virgil::sdk::crypto::keys::PublicKey;
using virgil::sdk::crypto::keys::KeyPair;
using virgil::sdk::VirgilHashAlgorithm;

const auto CustomParamKeySignature = VirgilByteArrayUtils::stringToBytes("VIRGIL-DATA-SIGNATURE");

Crypto::Crypto(const bool &useSHA256Fingerprints)
        : useSHA256Fingerprints_(useSHA256Fingerprints) {}

// Key management
KeyPair Crypto::generateKeyPair() const {
    auto keyPair = VirgilKeyPair::generateRecommended();

    auto keyPairId = computeHashForPublicKey(keyPair.publicKey());

    auto privateKey = PrivateKey(keyPair.privateKey(), keyPairId);
    auto publicKey = PublicKey(keyPair.publicKey(), keyPairId);

    return KeyPair(std::move(privateKey), std::move(publicKey));
}

PrivateKey Crypto::importPrivateKey(const VirgilByteArray &data, const std::string &password) const {
    auto privateKeyData = password.length() == 0 ?
         data : VirgilKeyPair::decryptPrivateKey(data, VirgilByteArrayUtils::stringToBytes(password));

    auto publicKey = VirgilKeyPair::extractPublicKey(privateKeyData, VirgilByteArray());

    auto keyIdentifier = computeHashForPublicKey(publicKey);

    auto exportedPrivateKeyData = VirgilKeyPair::privateKeyToDER(privateKeyData);

    return PrivateKey(std::move(exportedPrivateKeyData), std::move(keyIdentifier));
}

PublicKey Crypto::importPublicKey(const VirgilByteArray &data) const {
    auto keyIdentifier = computeHashForPublicKey(data);

    auto exportedPublicKey = VirgilKeyPair::publicKeyToDER(data);

    return PublicKey(std::move(exportedPublicKey), std::move(keyIdentifier));
}

PublicKey Crypto::extractPublicKeyFromPrivateKey(const PrivateKey &privateKey) const {
    auto privateKeyData = exportPrivateKey(privateKey);
    auto publicKeyData = VirgilKeyPair::extractPublicKey(privateKeyData, VirgilByteArray());

    auto exportedPublicKey = VirgilKeyPair::publicKeyToDER(publicKeyData);

    return PublicKey(exportedPublicKey, privateKey.identifier());
}

VirgilByteArray Crypto::exportPrivateKey(const PrivateKey &privateKey, const std::string &password) const {
    if (password.length() == 0)
        return VirgilKeyPair::privateKeyToDER(privateKey.key());

    auto passwordBytes = VirgilByteArrayUtils::stringToBytes(password);

    auto encryptedPrivateKeyData =
        VirgilKeyPair::encryptPrivateKey(privateKey.key(), passwordBytes);

    return VirgilKeyPair::privateKeyToDER(encryptedPrivateKeyData, passwordBytes);
}

VirgilByteArray Crypto::exportPublicKey(const PublicKey &publicKey) const {
    return VirgilKeyPair::publicKeyToDER(publicKey.key());
}


// Crypto operations

VirgilByteArray Crypto::encrypt(const VirgilByteArray &data, const std::vector<PublicKey> &recipients) const {
    auto cipher = VirgilCipher();

    for (auto& recipient : recipients) {
        auto publicKeyData = exportPublicKey(recipient);

        cipher.addKeyRecipient(recipient.identifier(), publicKeyData);
    }

    return cipher.encrypt(data);
}

void Crypto::encrypt(std::istream &istream, std::ostream &ostream, const std::vector<PublicKey> &recipients) const {
    auto cipher = VirgilChunkCipher();

    for (auto& recipient : recipients) {
        auto publicKeyData = exportPublicKey(recipient);

        cipher.addKeyRecipient(recipient.identifier(), publicKeyData);
    }

    auto dataSource = VirgilStreamDataSource(istream);
    auto dataSink = VirgilStreamDataSink(ostream);

    cipher.encrypt(dataSource, dataSink);
}

bool Crypto::verify(const VirgilByteArray &data, const VirgilByteArray &signature,
                    const PublicKey &signerPublicKey) const {
    auto signer = VirgilSigner();

    auto signerPublicKeyData = exportPublicKey(signerPublicKey);

    return signer.verify(data, signature, signerPublicKeyData);
}

bool Crypto::verify(std::istream &istream, const VirgilByteArray &signature, const PublicKey &signerPublicKey) const {
    auto signer = VirgilStreamSigner();

    auto signerPublicKeyData = exportPublicKey(signerPublicKey);

    auto dataSource = VirgilStreamDataSource(istream);

    return signer.verify(dataSource, signature, signerPublicKeyData);
}

VirgilByteArray Crypto::decrypt(const VirgilByteArray &data, const PrivateKey &privateKey) const {
    auto cipher = VirgilCipher();

    auto privateKeyData = exportPrivateKey(privateKey);

    return cipher.decryptWithKey(data, privateKey.identifier(), privateKeyData);
}

void Crypto::decrypt(std::istream &istream, std::ostream &ostream, const PrivateKey &privateKey) const {
    auto cipher = VirgilChunkCipher();

    auto privateKeyData = exportPrivateKey(privateKey);

    auto dataSource = VirgilStreamDataSource(istream);
    auto dataSink = VirgilStreamDataSink(ostream);

    cipher.decryptWithKey(dataSource, dataSink, privateKey.identifier(), privateKeyData);
}

VirgilByteArray Crypto::signThenEncrypt(const VirgilByteArray &data, const PrivateKey &privateKey,
                                        const std::vector<PublicKey> &recipients) const {
    auto signer = VirgilSigner();

    auto privateKeyData = exportPrivateKey(privateKey);

    auto signature = signer.sign(data, privateKeyData);

    auto cipher = VirgilCipher();

    cipher.customParams().setData(CustomParamKeySignature, signature);

    for (auto& recipient : recipients) {
        auto publicKeyData = exportPublicKey(recipient);

        cipher.addKeyRecipient(recipient.identifier(), publicKeyData);
    }

    return cipher.encrypt(data);
}

VirgilByteArray Crypto::decryptThenVerify(const VirgilByteArray &data, const PrivateKey &privateKey,
                                          const PublicKey &signerPublicKey) const {
    auto cipher = VirgilCipher();

    auto privateKeyData = exportPrivateKey(privateKey);
    auto decryptedData = cipher.decryptWithKey(data, privateKey.identifier(), privateKeyData);

    auto signature = cipher.customParams().getData(CustomParamKeySignature);

    auto signer = VirgilSigner();
    auto publicKeyData = exportPublicKey(signerPublicKey);
    auto isVerified = signer.verify(decryptedData, signature, publicKeyData);

    if (!isVerified) {
        throw make_error(VirgilSdkError::VerificationFailed, "Invalid signature.");
    }

    return decryptedData;
}

VirgilByteArray Crypto::generateSignature(const VirgilByteArray &data, const PrivateKey &privateKey) const {
    auto signer = VirgilSigner();

    auto privateKeyData = exportPrivateKey(privateKey);

    return signer.sign(data, privateKeyData);
}

VirgilByteArray Crypto::generateSignature(std::istream &istream, const PrivateKey &privateKey) const {
    auto signer = VirgilStreamSigner();

    auto dataSource = VirgilStreamDataSource(istream);
    auto privateKeyData = exportPrivateKey(privateKey);

    return signer.sign(dataSource, privateKeyData);
}

//Utils
Fingerprint Crypto::calculateFingerprint(const VirgilByteArray &data) const {
    return Fingerprint(computeHash(data, VirgilHashAlgorithm::SHA512));
}

VirgilByteArray Crypto::computeHash(const VirgilByteArray &data, VirgilHashAlgorithm algorithm) const {
    auto hash = VirgilHash(algorithm);
    return hash.hash(data);
}

VirgilByteArray Crypto::computeHashForPublicKey(const VirgilByteArray &publicKey) const {
    if (useSHA256Fingerprints_)
        return computeHash(VirgilKeyPair::publicKeyToDER(publicKey), VirgilHashAlgorithm::SHA256);
    else {
        VirgilByteArray hash = computeHash(VirgilKeyPair::publicKeyToDER(publicKey), VirgilHashAlgorithm::SHA512);
        hash.resize(8);
        return hash;
    }
}

const bool Crypto::useSHA256Fingerprints() const {
    return useSHA256Fingerprints_;
}
