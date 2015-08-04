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

#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>
#include <stdexcept>

#include <virgil/crypto/VirgilByteArray.h>
using virgil::crypto::VirgilByteArray;
#include <virgil/crypto/VirgilCryptoException.h>
using virgil::crypto::VirgilCryptoException;
#include <virgil/crypto/VirgilStreamCipher.h>
using virgil::crypto::VirgilStreamCipher;

#include <virgil/crypto/stream/VirgilStreamDataSource.h>
using virgil::crypto::stream::VirgilStreamDataSource;
#include <virgil/crypto/stream/VirgilStreamDataSink.h>
using virgil::crypto::stream::VirgilStreamDataSink;

#include <virgil/sdk/keys/model/PublicKey.h>
using virgil::sdk::keys::model::PublicKey;

#include <virgil/sdk/keys/io/marshaller.h>
using virgil::sdk::keys::io::marshaller;

int main() {
    try {
        std::cout << "Prepare input file: test.txt.enc..." << std::endl;
        std::ifstream inFile("test.txt.enc", std::ios::in | std::ios::binary);
        if (!inFile.good()) {
            throw std::runtime_error("can not read file: test.txt.enc");
        }

        std::cout << "Prepare output file: decrypted_test.txt..." << std::endl;
        std::ofstream outFile("decrypted_test.txt", std::ios::out | std::ios::binary);
        if (!outFile.good()) {
            throw std::runtime_error("can not write file: decrypted_test.txt");
        }

        std::cout << "Initialize cipher..." << std::endl;
        VirgilStreamCipher cipher;

        std::cout << "Read virgil public key..." << std::endl;
        std::ifstream publicKeyFile("virgil_public.key", std::ios::in | std::ios::binary);
        if (!publicKeyFile.good()) {
            throw std::runtime_error("can not read virgil public key: virgil_public.key");
        }
        std::string publicKeyData;
        std::copy(std::istreambuf_iterator<char>(publicKeyFile), std::istreambuf_iterator<char>(),
                std::back_inserter(publicKeyData));

        PublicKey publicKey = marshaller<PublicKey>::fromJson(publicKeyData);

        std::cout << "Read private key..." << std::endl;
        std::ifstream keyFile("private.key", std::ios::in | std::ios::binary);
        if (!keyFile.good()) {
            throw std::runtime_error("can not read private key: private.key");
        }
        VirgilByteArray privateKey;
        std::copy(std::istreambuf_iterator<char>(keyFile), std::istreambuf_iterator<char>(),
                std::back_inserter(privateKey));

        std::cout << "Decrypt..." << std::endl;
        VirgilStreamDataSource dataSource(inFile);
        VirgilStreamDataSink dataSink(outFile);
        cipher.decryptWithKey(dataSource, dataSink, virgil::crypto::str2bytes(publicKey.publicKeyId()), privateKey);
        std::cout << "Decrypted data is successfully stored in the output file..." << std::endl;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
    }
    return 0;
}
