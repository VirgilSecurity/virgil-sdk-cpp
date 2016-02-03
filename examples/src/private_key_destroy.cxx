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

#include <virgil/sdk/VirgilHub.h>
#include <virgil/sdk/VirgilUri.h>
#include <virgil/sdk/io/Marshaller.h>

using virgil::crypto::VirgilByteArray;

using virgil::sdk::VirgilHub;
using virgil::sdk::VirgilUri;
using virgil::sdk::Credentials;
using virgil::sdk::model::Identity;
using virgil::sdk::model::IdentityType;
using virgil::sdk::model::IdentityToken;
using virgil::sdk::model::VirgilCard;
using virgil::sdk::io::Marshaller;

const std::string VIRGIL_ACCESS_TOKEN = "eyJpZCI6IjIxMDk4ZjhlLWFjMzQtNGFkYy04YTBmLWFkZmM1YzBhNWE0OSIsImFwcGxpY2"
                                        "F0aW9uX2NhcmRfaWQiOiI2OWRlYzc1MC1hMDNmLTRmNmYtYTJlYi1iNTE2MzJkZmE3MTIiL"
                                        "CJ0dGwiOi0xLCJjdGwiOi0xLCJwcm9sb25nIjowfQ==.MIGaMA0GCWCGSAFlAwQCAgUABIGI"
                                        "MIGFAkEAhc7LGcy2qyRBJLsZu1Casdr6pcoub/pR3j1SB4E0HFx+XlfPqE9xIViG/Em3l+y2"
                                        "EkFvvjbSWdaMkHroO+UmOQJAMMEZB7rAynJuUog8ZbxabsYZ5TUtnOfRCIdkjYq+26BDIA7d"
                                        "n9lSE1s8TstZHP9f/ICmc2SMgAV7okyyomm5uQ==";
const std::string VIRGIL_PRIVATE_KEYS_SERVICE_URI_BASE = "https://keys-private-stg.virgilsecurity.com";
const std::string USER_EMAIL = "cpp.virgilsecurity@mailinator.com";
const std::string PRIVATE_KEY_PASSWORD = "qwerty";


int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << std::string("USAGE: ") + argv[0] + " <virgil_card_id>" << std::endl;
        return 1;
    }

    try {
        VirgilUri virgilUri;
        virgilUri.setPrivateKeyService(VIRGIL_PRIVATE_KEYS_SERVICE_URI_BASE);
        VirgilHub virgilHub(VIRGIL_ACCESS_TOKEN, virgilUri);
        virgilHub.loadServicePublicKeys();

        std::string virgilCardId = argv[1];

        std::cout << "Prepare input file: public.key..." << std::endl;
        std::ifstream inFile("public.key", std::ios::in | std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("can not read file: public.key");
        }
        std::cout << "Read public key..." << std::endl;
        VirgilByteArray publicKey;
        std::copy(std::istreambuf_iterator<char>(inFile), std::istreambuf_iterator<char>(),
                std::back_inserter(publicKey));

        std::cout << "Read private key..." << std::endl;
        std::ifstream privateKeyFile("private.key", std::ios::in | std::ios::binary);
        if (!privateKeyFile) {
            throw std::runtime_error("can not read private key: private.key");
        }
        VirgilByteArray privateKey;
        std::copy(std::istreambuf_iterator<char>(privateKeyFile), std::istreambuf_iterator<char>(),
                std::back_inserter(privateKey));
        Credentials credentials(privateKey, PRIVATE_KEY_PASSWORD);

        std::cout << "Destroy a Private Key" << std::endl;
        virgilHub.privateKeys().destroy(virgilCardId, publicKey, credentials);

    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
        return 1;
    }

    return 0;
}
