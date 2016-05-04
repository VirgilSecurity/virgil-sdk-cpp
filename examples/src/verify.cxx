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
#include <vector>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilStreamSigner.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>

#include <virgil/sdk/ServicesHub.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

const std::string VIRGIL_ACCESS_TOKEN = "eyJpZCI6IjAwMmI1NzY0LTBmOTgtNDUyMC04YjA0LTc0ZmYxYjNl"
                                        "NmYyMSIsImFwcGxpY2F0aW9uX2NhcmRfaWQiOiIwMmJmOTIwYS1m"
                                        "MmI3LTQ1NzQtYTM1Ni0yYTY2MzVkOTdjMDUiLCJ0dGwiOi0xLCJj"
                                        "dGwiOi0xLCJwcm9sb25nIjowfQ==.MFgwDQYJYIZIAWUDBAICBQA"
                                        "ERzBFAiEA74ba/2MfdUu9ML2o9mVve5aC1U8rCGU1PY0u0v/luJY"
                                        "CIAhKKHF4u642FrtJ/aVX8XE4z1EGAs/FD707Fuh8SSnu";
int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << std::string("USAGE: ") + argv[0] + " <user_email>" << std::endl;
        return 1;
    }

    try {
        std::string userEmail = argv[1];

        std::cout << "Prepare input file: test.txt..." << std::endl;
        std::ifstream inFile("test.txt", std::ios::in | std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("can not read file: test.txt");
        }
        vcrypto::stream::VirgilStreamDataSource dataSource(inFile);

        std::cout << "Read virgil sign..." << std::endl;
        std::ifstream signFile("test.txt.sign", std::ios::in | std::ios::binary);
        if (!signFile) {
            throw std::runtime_error("can not read sign: test.txt.sign");
        }
        vcrypto::VirgilByteArray sign;
        std::copy(std::istreambuf_iterator<char>(signFile), std::istreambuf_iterator<char>(), std::back_inserter(sign));

        std::cout << "Get signer (" << userEmail << ") public key from the Virgil PKI service..." << std::endl;
        vsdk::ServicesHub servicesHub(VIRGIL_ACCESS_TOKEN);

        vsdk::dto::Identity identity(userEmail, "email");
        std::vector<vsdk::models::CardModel> recipientCards = servicesHub.card().search(identity, true);
        vsdk::models::PublicKeyModel recipientPublicKey = recipientCards.at(0).getPublicKey();

        vcrypto::VirgilStreamSigner signer;
        std::cout << "Verify data..." << std::endl;
        bool verified = signer.verify(dataSource, sign, recipientPublicKey.getKey());
        std::cout << "Data is " << (verified ? "" : "not ") << "verified!" << std::endl;

    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
        return 1;
    }

    return 0;
}
