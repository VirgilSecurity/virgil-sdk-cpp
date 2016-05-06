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
#include <virgil/sdk/io/Marshaller.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

const std::string PRIVATE_KEY_PASSWORD = "qwerty";

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << std::string("USAGE: ") + argv[0] + " <user_email>" + " <path_public_key>" + " <path_private_key>"
                  << std::endl;
        return 1;
    }

    try {
        std::string pathVirgilAccessToken = "virgil_access_token.txt";
        std::ifstream inVirgilAccessTokenFile(pathVirgilAccessToken, std::ios::in | std::ios::binary);
        if (!inVirgilAccessTokenFile) {
            throw std::runtime_error("can not read file: " + pathVirgilAccessToken);
        }
        std::string virgilAccessToken((std::istreambuf_iterator<char>(inVirgilAccessTokenFile)),
                                      std::istreambuf_iterator<char>());

        std::string userEmail = argv[1];
        std::string pathPublicKey = argv[2];
        std::string pathPrivateKey = argv[3];

        vsdk::ServicesHub servicesHub(virgilAccessToken);
        vsdk::dto::Identity identity(userEmail, "email");

        std::cout << "Prepare public key file: " << pathPublicKey << std::endl;
        std::ifstream inPublicKeyFile(pathPublicKey, std::ios::in | std::ios::binary);
        if (!inPublicKeyFile) {
            throw std::runtime_error("can not read file: " + pathPublicKey);
        }
        std::cout << "Read public key..." << std::endl;
        vcrypto::VirgilByteArray publicKey;
        std::copy(std::istreambuf_iterator<char>(inPublicKeyFile), std::istreambuf_iterator<char>(),
                  std::back_inserter(publicKey));

        std::cout << "Prepare private key file: " << pathPrivateKey << std::endl;
        std::cout << "Read private key..." << std::endl;
        std::ifstream inPrivateKeyFile(pathPrivateKey, std::ios::in | std::ios::binary);
        if (!inPrivateKeyFile) {
            throw std::runtime_error("can not read private key: " + pathPrivateKey);
        }
        vcrypto::VirgilByteArray privateKey;
        std::copy(std::istreambuf_iterator<char>(inPrivateKeyFile), std::istreambuf_iterator<char>(),
                  std::back_inserter(privateKey));

        vsdk::Credentials credentials(privateKey, virgil::crypto::str2bytes(PRIVATE_KEY_PASSWORD));

        std::cout << "Create a Virgil Card" << std::endl;
        vsdk::models::CardModel card;
        card = servicesHub.card().create(identity, publicKey, credentials, {{"key", "value"}});
        std::string cardStr = vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(card);

        std::cout << "Virgil Card:" << std::endl;
        std::cout << cardStr << std::endl;

    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
        return 1;
    }

    return 0;
}
