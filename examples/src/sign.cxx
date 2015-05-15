/**
 * Copyright (C) 2014 Virgil Security Inc.
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

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;
#include <virgil/service/VirgilStreamSigner.h>
using virgil::service::VirgilStreamSigner;
#include <virgil/stream/VirgilStreamDataSource.h>
using virgil::stream::VirgilStreamDataSource;
#include <virgil/service/data/VirgilSign.h>
using virgil::service::data::VirgilSign;
#include <virgil/stream/utils.h>

int main() {
    try {
        std::cout << "Prepare input file: test.txt..." << std::endl;
        std::ifstream inFile("test.txt", std::ios::in | std::ios::binary);
        if (!inFile.good()) {
            throw std::invalid_argument("can not read file: test.txt");
        }

        std::cout << "Prepare output file: test.txt.sign..." << std::endl;
        std::ofstream outFile("test.txt.sign", std::ios::out | std::ios::binary);
        if (!outFile.good()) {
            throw std::invalid_argument("can not write file: test.txt.sign");
        }

        std::cout << "Read virgil public key..." << std::endl;
        VirgilCertificate virgilPublicKey = virgil::stream::read_certificate("virgil_public.key");

        std::cout << "Read private key..." << std::endl;
        std::ifstream keyFile("private.key", std::ios::in | std::ios::binary);
        if (!keyFile.good()) {
            throw std::invalid_argument("can not read private key: private.key");
        }
        VirgilByteArray privateKey;
        std::copy(std::istreambuf_iterator<char>(keyFile), std::istreambuf_iterator<char>(),
                std::back_inserter(privateKey));
        VirgilByteArray privateKeyPassword = virgil::str2bytes("password");

        std::cout << "Initialize signer..." << std::endl;
        VirgilStreamSigner signer;

        std::cout << "Sign data..." << std::endl;
        VirgilStreamDataSource dataSource(inFile);
        VirgilSign sign = signer.sign(dataSource, virgilPublicKey.id().certificateId(),
                privateKey, privateKeyPassword);

        std::cout << "Save sign..." << std::endl;
        VirgilByteArray signData = sign.toAsn1();
        std::copy(signData.begin(), signData.end(), std::ostreambuf_iterator<char>(outFile));
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
    }
    std::cout << "Sign is successfully stored in the output file." << std::endl;
    return 0;
}
