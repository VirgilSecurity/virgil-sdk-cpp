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

#include <cstddef>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>
#include <stdexcept>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;
#include <virgil/stream/VirgilStreamDataSource.h>
using virgil::stream::VirgilStreamDataSource;
#include <virgil/stream/VirgilStreamDataSink.h>
using virgil::stream::VirgilStreamDataSink;
#include <virgil/crypto/VirgilStreamCipher.h>
using virgil::crypto::VirgilStreamCipher;
#include <virgil/crypto/base/VirgilBase64.h>
using virgil::crypto::base::VirgilBase64;

#include <virgil/pki/model/Account.h>
using virgil::pki::model::Account;
#include <virgil/pki/model/PublicKey.h>
using virgil::pki::model::PublicKey;
#include <virgil/pki/http/ConnectionBase.h>
using virgil::pki::http::ConnectionBase;
#include <virgil/pki/client/PublicKeyClientBase.h>
using virgil::pki::client::PublicKeyClientBase;

static const std::string VIRGIL_PKI_URL_BASE = "https://pki-stg.virgilsecurity.com/v1/";
static const std::string VIRGIL_PKI_APP_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
static const std::string USER_ID = "test.virgilsecurity@mailinator.com";

#define MAKE_URL(base, path) (base path)

int main() {
    try {
        std::cout << "Prepare input file: test.txt..." << std::endl;
        std::ifstream inFile("test.txt", std::ios::in | std::ios::binary);
        if (!inFile.good()) {
            throw std::runtime_error("can not read file: test.txt");
        }

        std::cout << "Prepare output file: test.txt.enc..." << std::endl;
        std::ofstream outFile("test.txt.enc", std::ios::out | std::ios::binary);
        if (!outFile.good()) {
            throw std::runtime_error("can not write file: test.txt.enc");
        }

        std::cout << "Initialize cipher..." << std::endl;
        VirgilStreamCipher cipher;

        std::cout << "Get recipient ("<< USER_ID << ") information from the Virgil PKI service..." << std::endl;
        PublicKeyClientBase publicKeyClient(
                std::make_shared<ConnectionBase>(VIRGIL_PKI_APP_TOKEN, VIRGIL_PKI_URL_BASE));
        std::vector<Account> accounts = publicKeyClient.search(USER_ID);
        if (accounts.empty() || accounts.front().publicKeys().empty()) {
            throw std::runtime_error(std::string("Recipient with id: ") + USER_ID + " not found.");
        }
        std::cout << "Add recipient..." << std::endl;
        PublicKey publicKey = accounts.front().publicKeys().front();
        cipher.addKeyRecipient(virgil::str2bytes(publicKey.publicKeyId()), publicKey.key());

        std::cout << "Encrypt and store results..." << std::endl;
        VirgilStreamDataSource dataSource(inFile);
        VirgilStreamDataSink dataSink(outFile);
        cipher.encrypt(dataSource, dataSink, true);

        std::cout << "Encrypted data is successfully stored in the output file..." << std::endl;
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
    }
    return 0;
}
