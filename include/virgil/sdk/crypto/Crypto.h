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

#ifndef VIRGIL_SDK_CRYPTO_H
#define VIRGIL_SDK_CRYPTO_H

#include <virgil/sdk/Common.h>
#include <virgil/sdk/crypto/keys/KeyPair.h>

namespace virgil {
namespace sdk {
    namespace crypto {
        class Crypto {
        public:
            Crypto(const bool &useSHA256Fingerprints = false);

            keys::KeyPair generateKeyPair() const;

            keys::PrivateKey importPrivateKey(const VirgilByteArray &data,
                                              const std::string& password = "") const;

            keys::PublicKey importPublicKey(const VirgilByteArray &data) const;

            keys::PublicKey extractPublicKeyFromPrivateKey(const keys::PrivateKey &privateKey) const;

            VirgilByteArray exportPrivateKey(const keys::PrivateKey &privateKey,
                                             const std::string &password = "") const;

            VirgilByteArray exportPublicKey(const keys::PublicKey &publicKey) const;

            VirgilByteArray encrypt(const VirgilByteArray &data,
                                    const std::vector<keys::PublicKey> &recipients) const;

            void encrypt(std::istream &istream, std::ostream &ostream,
                         const std::vector<keys::PublicKey> &recipients) const;

            bool verify(const VirgilByteArray &data, const VirgilByteArray &signature,
                        const keys::PublicKey &signerPublicKey) const;

            bool verify(std::istream &istream, const VirgilByteArray &signature,
                        const keys::PublicKey &signerPublicKey) const;

            VirgilByteArray decrypt(const VirgilByteArray &data, const keys::PrivateKey &privateKey) const;

            void decrypt(std::istream &istream, std::ostream &ostream,
                         const keys::PrivateKey &privateKey) const;

            VirgilByteArray signThenEncrypt(const VirgilByteArray &data, const keys::PrivateKey &privateKey,
                                            const std::vector<keys::PublicKey> &recipients) const;

            VirgilByteArray decryptThenVerify(const VirgilByteArray &data, const keys::PrivateKey &privateKey,
                                              const keys::PublicKey &signerPublicKey) const;

            VirgilByteArray generateSignature(const VirgilByteArray &data,
                                              const keys::PrivateKey &privateKey) const;

            VirgilByteArray generateSignature(std::istream &istream, const keys::PrivateKey &privateKey) const;

            VirgilByteArray generateSHA512(const VirgilByteArray &data) const;

            /*!
             * @brief Computes hash of data using selected algorithm.
             * @param data data of which hash is computed
             * @param algorithm hash algorithm
             * @return hash
             */
            VirgilByteArray computeHash(const VirgilByteArray &data, VirgilHashAlgorithm algorithm) const;

            const bool useSHA256Fingerprints() const;
        private:
            bool useSHA256Fingerprints_;
            VirgilByteArray computeHashForPublicKey(const VirgilByteArray &publicKey) const;
        };
    }
}
}

#endif //VIRGIL_SDK_CRYPTO_H
