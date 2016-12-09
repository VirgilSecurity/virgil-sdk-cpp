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

#ifndef VIRGIL_SDK_CRYPTOINTERFACE_H
#define VIRGIL_SDK_CRYPTOINTERFACE_H

#include <virgil/sdk/Common.h>
#include <virgil/sdk/crypto/keys/KeyPair.h>
#include <virgil/sdk/crypto/Fingerprint.h>

namespace virgil {
namespace sdk {
    namespace crypto {
        /*!
         * @brief Interface for all cryptographic operations.
         */
        class CryptoInterface {
        public:
            /*!
             * @brief Generates key pair using ed25519 algorithm.
             * @see KeyPair
             * @return generated KeyPair instance
             */
            virtual keys::KeyPair generateKeyPair() const = 0;

            /*!
             * @brief Imports Private Key with password from raw representation.
             * @param data Raw representation of Private Key
             * @param password std::string password for Private Key
             * @return imported PrivateKey instance
             */
            virtual keys::PrivateKey importPrivateKey(const VirgilByteArray &data,
                                                      const std::string& password = "") const = 0;

            /*!
             * @brief Imports Public Key from raw representation.
             * @param data raw representation of Public Key
             * @return imported PublicKey instance
             */
            virtual keys::PublicKey importPublicKey(const VirgilByteArray &data) const = 0;

            /*!
             * @brief Extracts corresponding Public Key from Private Key.
             * @param privateKey PrivateKey instance
             * @return extracted PublicKey instance with Public Key which corresponds to given Private Key
             */
            virtual keys::PublicKey extractPublicKeyFromPrivateKey(const keys::PrivateKey &privateKey) const = 0;

            /*!
             * @brief Exports Private Key to raw representation.
             * @param privateKey PrivateKey instance
             * @param password std::string password for Private Key export (required for further import)
             * @return raw representation of Private Key
             */
            virtual VirgilByteArray exportPrivateKey(const keys::PrivateKey &privateKey,
                                                     const std::string &password = "") const = 0;

            /*!
             * @brief Exports Public Key to raw representation.
             * @param publicKey PublicKey instance
             * @return raw representation of Public Key
             */
            virtual VirgilByteArray exportPublicKey(const keys::PublicKey &publicKey) const = 0;

            /*!
             * @brief Encrypts data.
             * @note Only those, who have Private Key corresponding to one of Public Keys in recipients vector
             *       will be able to decrypt data.
             * @param data data to be encrypted
             * @param recipients std::vector of PublicKey instances with recipients' Public Keys
             * @return encrypted data
             */
            virtual VirgilByteArray encrypt(const VirgilByteArray &data,
                                            const std::vector<keys::PublicKey> &recipients) const = 0;

            /*!
             * @brief Encrypts stream.
             * @note Only those, who have Private Key corresponding to one of Public Keys in recipients vector
             *       will be able to decrypt data.
             * @param istream std::istream with data to be encrypted
             * @param ostream std::ostream where encrypted data will be pushed
             * @param recipients std::vector of PublicKey instances with recipients' Public Keys
             */
            virtual void encrypt(std::istream &istream, std::ostream &ostream,
                                 const std::vector<keys::PublicKey> &recipients) const = 0;

            /*!
             * @brief Verifies data for genuineness.
             * @param data data to be verified
             * @param signature Signature
             * @param signerPublicKey PublicKey instance with signer's Public Key
             * @return true if data was successfully verified, false otherwise
             */
            virtual bool verify(const VirgilByteArray &data, const VirgilByteArray &signature,
                                const keys::PublicKey &signerPublicKey) const = 0;

            /*!
             * @brief Verifies stream for genuineness.
             * @param istream std::istream with data to be verified
             * @param signature Signatue
             * @param signerPublicKey PublicKey instance with signer's Public Keys
             * @return true if data was successfully verified, false otherwise
             */
            virtual bool verify(std::istream &istream, const VirgilByteArray &signature,
                                const keys::PublicKey &signerPublicKey) const = 0;

            /*!
             * @brief Decrypts data.
             * @param data data to be decrypted
             * @param privateKey Private Key of data recipient
             * @return decrypted data
             */
            virtual VirgilByteArray decrypt(const VirgilByteArray &data, const keys::PrivateKey &privateKey) const = 0;

            /*!
             * @brief Decrypts stream.
             * @param istream std::istream with data to be decrypted
             * @param ostream std::ostream where decrypted data will be pushed
             * @param privateKey Private Key of data recipient
             */
            virtual void decrypt(std::istream &istream, std::ostream &ostream,
                                 const keys::PrivateKey &privateKey) const = 0;

            /*!
             * @brief Signs and encrypts data.
             * @param data data to be signed and encrypted
             * @param privateKey Private Key of signer
             * @param recipients std::vector of PublicKey instances with recipients' Public Keys
             * @return signed and encrypted data
             */
            virtual VirgilByteArray signThenEncrypt(const VirgilByteArray &data,
                                                    const keys::PrivateKey &privateKey,
                                                    const std::vector<keys::PublicKey> &recipients) const = 0;

            /*!
             * @brief Decrypts and verifies data.
             * @param data signed and encrypted data
             * @param privateKey Private Key of recipient
             * @param signerPublicKey signer's Public Key
             * @return decrypted and verified data
             */
            virtual VirgilByteArray decryptThenVerify(const VirgilByteArray &data,
                                                      const keys::PrivateKey &privateKey,
                                                      const keys::PublicKey &signerPublicKey) const = 0;

            /*!
             * @brief Generates signature for data.
             * @param data data from which signature will be generated
             * @param privateKey signer's Private Key
             * @return Signature for data
             */
            virtual VirgilByteArray generateSignature(const VirgilByteArray &data,
                                                      const keys::PrivateKey &privateKey) const = 0;

            /*!
             * @brief Generates signature for stream.
             * @param istream std::istream with data from which signature will be generated
             * @param privateKey signer's Private Key
             * @return Signature for stream
             */
            virtual VirgilByteArray generateSignature(std::istream &istream, const
                                                      keys::PrivateKey &privateKey) const = 0;

            /*!
             * @brief Calculates Fingerprint for data.
             * @param data data from which Fingerprint will be calculated
             * @return Fingerprint
             */
            virtual Fingerprint calculateFingerprint(const VirgilByteArray &data) const = 0;

            /*!
             * @brief Virtual destructor.
             */
            virtual ~CryptoInterface() = default;
        };
    }
}
}

#endif //VIRGIL_SDK_CRYPTOINTERFACE_H
