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

#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilStreamSigner.h>
#include <virgil/crypto/VirgilSigner.h>
#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/crypto/stream/VirgilStreamDataSource.h>

namespace vcrypto = virgil::crypto;

const std::string PRIVATE_KEY_PASSWORD = "qwerty";

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << std::string("USAGE: ") + argv[0] + " <path_private_key>" << std::endl;
    }

    try {
        std::string pathPrivateKey = argv[1];

        std::cout << "Prepare input file: test.txt..." << std::endl;
        std::ifstream inFile("test.txt", std::ios::in | std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("can not read file: test.txt");
        }
        vcrypto::stream::VirgilStreamDataSource dataSource(inFile);

        std::cout << "Prepare private key file: " << pathPrivateKey << std::endl;
        std::cout << "Read private key..." << std::endl;
        std::ifstream inPrivateKeyFile(pathPrivateKey, std::ios::in | std::ios::binary);
        if (!inPrivateKeyFile) {
            throw std::runtime_error("can not read private key: " + pathPrivateKey);
        }
        vcrypto::VirgilByteArray privateKey;
        std::copy(std::istreambuf_iterator<char>(inPrivateKeyFile), std::istreambuf_iterator<char>(),
                  std::back_inserter(privateKey));

        vcrypto::VirgilStreamSigner streamSigner;

        std::cout << "Sign data..." << std::endl;
        vcrypto::VirgilByteArray streamSign =
            streamSigner.sign(dataSource, privateKey, vcrypto::str2bytes(PRIVATE_KEY_PASSWORD));

        std::cout << "Prepare output file: test.txt.sign..." << std::endl;
        std::ofstream outFile("test.txt.sign", std::ios::out | std::ios::binary);
        if (!outFile) {
            throw std::runtime_error("can not write file: test.txt.sign");
        }

        std::cout << "Save sign..." << std::endl;
        std::copy(streamSign.begin(), streamSign.end(), std::ostreambuf_iterator<char>(outFile));
        std::cout << "Sign is successfully stored in the output file." << std::endl;

    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
        return 1;
    }

    return 0;
}
