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

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/foundation/VirgilBase64.h>
#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>
#include <virgil/crypto/stream/VirgilStreamDataSink.h>

namespace vcrypto = virgil::crypto;

const std::string PASSWORD = "qwerty";


int main() {
    try {
        vcrypto::VirgilStreamCipher cipher;

        std::cout << "Add recipient pass..." << "\n";
        vcrypto::VirgilByteArray recipientPwd = vcrypto::str2bytes(PASSWORD);
        cipher.addPasswordRecipient(recipientPwd);

        std::cout << "Prepare input file: test.txt..." << "\n";
        std::ifstream inFile("test.txt", std::ios::in | std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("can not read file: test.txt");
        }
        vcrypto::stream::VirgilStreamDataSource dataSource(inFile);

        std::cout << "Prepare output file: test.txt.encp..." << "\n";
        std::ofstream outFile("test.txt.encp", std::ios::out | std::ios::binary);
        if (!outFile) {
            throw std::runtime_error("can not write file: test.txt.enc");
        }
        vcrypto::stream::VirgilStreamDataSink dataSink(outFile);

        std::cout << "Encrypt and store results..." << "\n";
        cipher.encrypt(dataSource, dataSink, true);
        std::cout << "Encrypted data with pass is successfully stored in the output file..." << "\n";

    } catch (std::exception& exception) {
        std::cerr << exception.what() << "\n";
        return 1;
    }

    return 0;
}
