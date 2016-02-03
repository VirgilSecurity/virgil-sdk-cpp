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
#include <vector>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilStreamCipher.h>
#include <virgil/crypto/foundation/VirgilBase64.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>
#include <virgil/crypto/stream/VirgilStreamDataSink.h>

#include <virgil/sdk/VirgilHub.h>
#include <virgil/sdk/VirgilUri.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilStreamCipher;
using virgil::crypto::foundation::VirgilBase64;
using virgil::crypto::stream::VirgilStreamDataSource;
using virgil::crypto::stream::VirgilStreamDataSink;

using virgil::sdk::VirgilHub;
using virgil::sdk::model::VirgilCard;
using virgil::sdk::model::PublicKey;
using virgil::sdk::model::Identity;
using virgil::sdk::model::IdentityType;
using virgil::sdk::VirgilUri;

const std::string VIRGIL_ACCESS_TOKEN = "eyJpZCI6IjIxMDk4ZjhlLWFjMzQtNGFkYy04YTBmLWFkZmM1YzBhNWE0OSIsImFwcGxpY2"
                                        "F0aW9uX2NhcmRfaWQiOiI2OWRlYzc1MC1hMDNmLTRmNmYtYTJlYi1iNTE2MzJkZmE3MTIiL"
                                        "CJ0dGwiOi0xLCJjdGwiOi0xLCJwcm9sb25nIjowfQ==.MIGaMA0GCWCGSAFlAwQCAgUABIGI"
                                        "MIGFAkEAhc7LGcy2qyRBJLsZu1Casdr6pcoub/pR3j1SB4E0HFx+XlfPqE9xIViG/Em3l+y2"
                                        "EkFvvjbSWdaMkHroO+UmOQJAMMEZB7rAynJuUog8ZbxabsYZ5TUtnOfRCIdkjYq+26BDIA7d"
                                        "n9lSE1s8TstZHP9f/ICmc2SMgAV7okyyomm5uQ==";
const std::string VIRGIL_PUBLIC_KEYS_SERVICE_URI_BASE = "https://keys-stg.virgilsecurity.com";
const std::string USER_EMAIL = "cpp.virgilsecurity@mailinator.com";


int main() {
    try {
        std::cout << "Get recipient ("<< USER_EMAIL << ") information from the Virgil PKI service..." << std::endl;

        VirgilUri virgilUri;
        virgilUri.setPublicKeyService(VIRGIL_PUBLIC_KEYS_SERVICE_URI_BASE);
        VirgilHub virgilHub(VIRGIL_ACCESS_TOKEN, virgilUri);
        virgilHub.loadServicePublicKeys();

        std::vector<VirgilCard> recipientCards = virgilHub.cards().search(Identity(USER_EMAIL, IdentityType::Email));

        VirgilStreamCipher cipher;
        std::cout << "Add recipient..." << std::endl;

        PublicKey recipientPublicKey = recipientCards.at(0).getPublicKey();
        cipher.addKeyRecipient(VirgilBase64::decode(recipientPublicKey.getId()), recipientPublicKey.getKey());

        std::cout << "Prepare input file: test.txt..." << std::endl;
        std::ifstream inFile("test.txt", std::ios::in | std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("can not read file: test.txt");
        }
        VirgilStreamDataSource dataSource(inFile);

        std::cout << "Prepare output file: test.txt.enc..." << std::endl;
        std::ofstream outFile("test.txt.enc", std::ios::out | std::ios::binary);
        if (!outFile) {
            throw std::runtime_error("can not write file: test.txt.enc");
        }
        VirgilStreamDataSink dataSink(outFile);

        std::cout << "Encrypt and store results..." << std::endl;
        cipher.encrypt(dataSource, dataSink, true);
        std::cout << "Encrypted data with key is successfully stored in the output file..." << std::endl;

    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
        return 1;
    }

    return 0;
}
