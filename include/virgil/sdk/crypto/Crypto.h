/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#ifndef VIRGIL_SDK_CRYPTO_H
#define VIRGIL_SDK_CRYPTO_H

#include <virgil/sdk/Common.h>
#include <virgil/sdk/crypto/keys/KeyPair.h>

namespace virgil {
namespace sdk {
    namespace crypto {
        /*!
         * @brief Class for high level interactions with crypto library
         */
        class Crypto {
        public:
            /*!
             * @brief Constructor
             * @param useSHA256Fingerprints use old algorithm to generate key fingerprints
             * @note Current algorithm: first 8 bytes of SHA512 of public key in DER format.
             * Old algorithm SHA256 of public key in DER format.
             * Use SHA256 fingerprint only if you need to work with encrypted data,
             * that was encrypted using those fingerprint.
             */
            Crypto(bool useSHA256Fingerprints = false);

            /*!
             * @brief Generates KeyPair of default key type
             * @return generated KeyPair
             */
            keys::KeyPair generateKeyPair() const;

            /*!
             * @brief Imports private key from raw data in DER or PEM format
             * @param data Private Key in DER or PEM format
             * @param password password, if password is encrypted
             * @return
             */
            keys::PrivateKey importPrivateKey(const VirgilByteArray &data,
                                              const std::string& password = "") const;

            /*!
             * @brief Imports public key from DER or PEM format
             * @param data Public Key in DER or PEM format
             * @return imported Public Key
             */
            keys::PublicKey importPublicKey(const VirgilByteArray &data) const;

            /*!
             * @brief Extracts public key from private key
             * @param privateKey Private key to extract from
             * @return Public Key that matches passed Private Key
             */
            keys::PublicKey extractPublicKeyFromPrivateKey(const keys::PrivateKey &privateKey) const;

            /*!
             * @brief Exports encrypted using password private key
             * @param privateKey PrivateKey to export
             * @param password Password
             * @return exported encrypted private key
             */
            VirgilByteArray exportPrivateKey(const keys::PrivateKey &privateKey,
                                             const std::string &password = "") const;

            /*!
             * @brief Exports public key in DER format
             * @param publicKey PublicKey to export
             * @return exported public key in DER format
             */
            VirgilByteArray exportPublicKey(const keys::PublicKey &publicKey) const;

            /*!
             * @brief Encrypts data for passed PublicKeys
             * @param data data to be encrypted
             * @param recipients std::vector with recipient's Public Keys
             * @return encrypted data
             */
            VirgilByteArray encrypt(const VirgilByteArray &data,
                                    const std::vector<keys::PublicKey> &recipients) const;

            /*!
             * @brief Encrypts data stream for passed PublicKeys
             * @param istream stream to be encrypted
             * @param ostream stream with encrypted data
             * @param recipients std::vector with recipient's Public Keys
             */
            void encrypt(std::istream &istream, std::ostream &ostream,
                         const std::vector<keys::PublicKey> &recipients) const;

            /*!
             * @brief Verifies digital signature of data
             * @param data data that was signed
             * @param signature digital signature
             * @param signerPublicKey signer public key
             * @return true if signature is verified, else otherwise
             */
            bool verify(const VirgilByteArray &data, const VirgilByteArray &signature,
                        const keys::PublicKey &signerPublicKey) const;

            /*!
             * @brief Verifies digital signature of data stream
             * @param istream data stream that was signed
             * @param signature digital signature
             * @param signerPublicKey signer public key
             * @return true if signature is verified, else otherwise
             */
            bool verify(std::istream &istream, const VirgilByteArray &signature,
                        const keys::PublicKey &signerPublicKey) const;

            /*!
             * @brief Decrypts data using passed PrivateKey
             * @param data encrypted data
             * @param privateKey recipient's private key
             * @return decrypted data
             */
            VirgilByteArray decrypt(const VirgilByteArray &data, const keys::PrivateKey &privateKey) const;

            /*!
             * @brief Decrypts data stream using passed PrivateKey
             * @param istream stream with encrypted data
             * @param ostream stream with decrypted data
             * @param privateKey recipient's private key
             */
            void decrypt(std::istream &istream, std::ostream &ostream,
                         const keys::PrivateKey &privateKey) const;

            /*!
             * @brief Signs (with private key) Then Encrypts data for passed PublicKeys
             * @param data data to be signed, then encrypted
             * @param privateKey sender private key
             * @param recipients std::vector with recipient's Public Keys
             * @return signed, then encrypted data
             */
            VirgilByteArray signThenEncrypt(const VirgilByteArray &data, const keys::PrivateKey &privateKey,
                                            const std::vector<keys::PublicKey> &recipients) const;

            /*!
             * @brief Decrypts (with private key) Then Verifies data using signer PublicKey
             * @param data data to be signed, then verified
             * @param privateKey receiver's private key
             * @param signerPublicKey signer public key
             * @return decrypted, then verified data
             */
            VirgilByteArray decryptThenVerify(const VirgilByteArray &data, const keys::PrivateKey &privateKey,
                                              const keys::PublicKey &signerPublicKey) const;

            /*!
             * @brief Decrypts (with private key) Then Verifies data using any of signers' PublicKeys
             * @param data data to be signed, then verified
             * @param privateKey receiver's private key
             * @param signerPublicKey signer public key
             * @return decrypted, then verified data
             */
            VirgilByteArray decryptThenVerify(const VirgilByteArray &data, const keys::PrivateKey &privateKey,
                                              const std::vector<keys::PublicKey> &signersPublicKeys) const;

            /*!
             * @brief Generates digital signature of data using private key
             * @param data data to sign
             * @param privateKey Private Key to be used to generate signature
             * @return digital signature
             */
            VirgilByteArray generateSignature(const VirgilByteArray &data,
                                              const keys::PrivateKey &privateKey) const;

            /*!
             * @brief Generates digital signature of data stream using private key
             * @param istream data stream to sign
             * @param privateKey Private Key to be used to generate signature
             * @return digital signature
             */
            VirgilByteArray generateSignature(std::istream &istream, const keys::PrivateKey &privateKey) const;

            /*!
             * @brief Computes SHA-512
             * @param data data to be hashed
             * @return hash
             */
            VirgilByteArray generateSHA512(const VirgilByteArray &data) const;

            /*!
             * @brief Computes hash of data using selected algorithm.
             * @param data data of which hash is computed
             * @param algorithm hash algorithm
             * @return hash
             */
            VirgilByteArray computeHash(const VirgilByteArray &data, VirgilHashAlgorithm algorithm) const;

            /*!
             * @brief Getter
             * @return whether Crypto is using old algorithm to generate key fingerprints
             * @note Current algorithm: first 8 bytes of SHA512 of public key in DER format.
             * Old algorithm: SHA256 of public key in DER format.
             * Use SHA256 fingerprint only if you need to work with encrypted data,
             * that was encrypted using those fingerprint.
             */
            bool useSHA256Fingerprints() const;

        private:
            bool useSHA256Fingerprints_;

            VirgilByteArray computeHashForPublicKey(const VirgilByteArray &publicKey) const;
        };
    }
}
}

#endif //VIRGIL_SDK_CRYPTO_H