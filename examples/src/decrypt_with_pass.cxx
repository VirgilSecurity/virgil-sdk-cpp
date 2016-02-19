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
#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>
#include <virgil/crypto/stream/VirgilStreamDataSink.h>

#include <virgil/sdk/model/PublicKey.h>
#include <virgil/sdk/io/Marshaller.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

const std::string PASSWORD = "123456789";

int main() {
    try {
        //std::cout << "Prepare input file: test.txt.encp..." << std::endl;
        std::ifstream inFile("test.txt.encp", std::ios::in | std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("can not read file: test.txt.enc");
        }
        vcrypto::stream::VirgilStreamDataSource dataSource(inFile);

        //std::cout << "Prepare output file: decrypted_test.txt..." << std::endl;
        std::ofstream outFile("decrypted_testp.txt", std::ios::out | std::ios::binary);
        if (!outFile) {
            throw std::runtime_error("can not write file: decrypted_testp.txt");
        }
        vcrypto::stream::VirgilStreamDataSink dataSink(outFile);

        vcrypto::VirgilStreamCipher cipher;
        //std::cout << "Decrypt with pass..." << std::endl;
        cipher.decryptWithPassword(dataSource, dataSink, vcrypto::str2bytes(PASSWORD));
        //std::cout << "Decrypted data with pass is successfully stored in the output file..." << std::endl;

    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
        return 1;
    }

    return 0;
}
