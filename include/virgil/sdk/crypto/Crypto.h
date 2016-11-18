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

#include <virgil/sdk/crypto/CryptoInterface.h>
#include <virgil/sdk/crypto/Common.h>

namespace virgil {
namespace sdk {
    namespace crypto {
        class Crypto: public CryptoInterface {
        public:
            Crypto();

            // CryptoInterface implementation
            KeyPair generateKeyPair() const override;
            PrivateKey importPrivateKey(const VirgilByteArray &data, const std::string& password = "") const override;
            PublicKey importPublicKey(const VirgilByteArray &data) const override;
            PublicKey extractPublicKeyFromPrivateKey(const PrivateKey &privateKey) const override;
            VirgilByteArray exportPrivateKey(const PrivateKey &privateKey, const std::string &password = "") const override;
            VirgilByteArray exportPublicKey(const PublicKey &publicKey) const override;

            VirgilByteArray encrypt(const VirgilByteArray &data, const std::vector<PublicKey> &recipients) const override;
            void encrypt(std::istream &istream, std::ostream &ostream, const std::vector<PublicKey> &recipients) const override;
            bool verify(const VirgilByteArray &data, const VirgilByteArray &signature, const PublicKey &signerPublicKey) const override;
            bool verify(std::istream &istream, const VirgilByteArray &signature, const PublicKey &signerPublicKey) const override;
            VirgilByteArray decrypt(const VirgilByteArray &data, const PrivateKey &privateKey) const override;
            void decrypt(std::istream &istream, std::ostream &ostream, const PrivateKey &privateKey) const override;
            VirgilByteArray signThenEncrypt(const VirgilByteArray &data, const PrivateKey &privateKey, const std::vector<PublicKey> &recipients) const override;
            VirgilByteArray decryptThenVerify(const VirgilByteArray &data, const PrivateKey &privateKey, const PublicKey &signerPublicKey) const override;
            VirgilByteArray generateSignature(const VirgilByteArray &data, const PrivateKey &privateKey) const override;
            VirgilByteArray generateSignature(std::istream &istream, const PrivateKey &privateKey) const override;

        private:
            VirgilByteArray computeHashForPublicKey(const VirgilByteArray &publicKey) const;
        };
    }
}
}

#endif //VIRGIL_SDK_CRYPTO_H
