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

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/util/ValidationTokenGenerator.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

const std::string VIRGIL_ACCESS_TOKEN = "eyJpZCI6IjAwMmI1NzY0LTBmOTgtNDUyMC04YjA0LTc0ZmYxYjNl"
                                        "NmYyMSIsImFwcGxpY2F0aW9uX2NhcmRfaWQiOiIwMmJmOTIwYS1m"
                                        "MmI3LTQ1NzQtYTM1Ni0yYTY2MzVkOTdjMDUiLCJ0dGwiOi0xLCJj"
                                        "dGwiOi0xLCJwcm9sb25nIjowfQ==.MFgwDQYJYIZIAWUDBAICBQA"
                                        "ERzBFAiEA74ba/2MfdUu9ML2o9mVve5aC1U8rCGU1PY0u0v/luJY"
                                        "CIAhKKHF4u642FrtJ/aVX8XE4z1EGAs/FD707Fuh8SSnu";

const std::string APPLICATION_PASSWORD = "IDn)k\\0vT}CXM3V";

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << std::string("USAGE: ") + argv[0] + " <obfuscator_identity>" + " <path_app_private_key>"
                  << std::endl;
        return 1;
    }

    try {
        std::string obfuscatorIdentityValue = argv[1];
        std::string pathAppPrivateKey = argv[2];

        std::cout << "Prepare application private key file: " << pathAppPrivateKey << std::endl;
        std::cout << "Read application private key..." << std::endl;
        std::ifstream inAppPrivateKeyFile(pathAppPrivateKey, std::ios::in | std::ios::binary);
        if (!inAppPrivateKeyFile) {
            throw std::runtime_error("can not read private key: " + pathAppPrivateKey);
        }
        vcrypto::VirgilByteArray appPrivateKeyByteArray;
        std::copy(std::istreambuf_iterator<char>(inAppPrivateKeyFile), std::istreambuf_iterator<char>(),
                  std::back_inserter(appPrivateKeyByteArray));

        vsdk::Credentials appCredentials(appPrivateKeyByteArray, virgil::crypto::str2bytes(APPLICATION_PASSWORD));
        vsdk::models::IdentityModel::Type identityType = vsdk::models::IdentityModel::Type::Custom;

        std::cout << "Generatin a validation token " << std::endl;
        std::string validationToken =
            vsdk::util::ValidationTokenGenerator::generate(obfuscatorIdentityValue, identityType, appCredentials);

        std::cout << "The validation token generated " << std::endl;
        std::cout << validationToken << std::endl;

    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
        return 1;
    }

    return 0;
}
