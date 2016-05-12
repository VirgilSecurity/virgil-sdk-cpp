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
#include <virgil/crypto/VirgilKeyPair.h>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/io/Marshaller.h>
#include <virgil/sdk/util/obfuscator.h>
#include <virgil/sdk/util/token.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

int main(int argc, char** argv) {
    try {
        std::cout << "1. Obfuscator identity\n";
        std::string userIdentityValue = "bob@mailinator.com";
        std::string userIdentityType = "email";

        std::string obfuscatorIdentityValue = vsdk::util::obfuscate(userIdentityValue, "salt");
        std::string obfuscatorIdentityType = vsdk::util::obfuscate(userIdentityType, "salt");

        std::cout << "2. Generation Validation Token\n";
        std::string pathAppPrivateKey = "application_keys/private.key";
        std::ifstream inAppPrivateKeyFile(pathAppPrivateKey, std::ios::in | std::ios::binary);
        if (!inAppPrivateKeyFile) {
            throw std::runtime_error("can not read private key: " + pathAppPrivateKey);
        }
        vcrypto::VirgilByteArray appPrivateKeyByteArray;
        std::copy(std::istreambuf_iterator<char>(inAppPrivateKeyFile), std::istreambuf_iterator<char>(),
                  std::back_inserter(appPrivateKeyByteArray));

        std::string kApplicationPasswoord = "<APPLICATION_PRIVATE_KEY_PASSWORD>";
        vsdk::Credentials appCredentials(appPrivateKeyByteArray, virgil::crypto::str2bytes(kApplicationPasswoord));

        std::string validationToken1 =
            vsdk::util::generate_validation_token(obfuscatorIdentityValue, obfuscatorIdentityType, appCredentials);

        std::cout << "3. Create a Private Virgil Card\n";
        std::string pathVirgilAccessToken = "virgil_access_token.txt";
        std::ifstream inVirgilAccessTokenFile(pathVirgilAccessToken, std::ios::in | std::ios::binary);
        if (!inVirgilAccessTokenFile) {
            throw std::runtime_error("can not read file: " + pathVirgilAccessToken);
        }
        std::string virgilAccessToken((std::istreambuf_iterator<char>(inVirgilAccessTokenFile)),
                                      std::istreambuf_iterator<char>());

        std::string kPrivateKeyPassword = "qwerty";
        vcrypto::VirgilKeyPair newKeyPair(vcrypto::str2bytes(kPrivateKeyPassword));
        vcrypto::VirgilByteArray publicKey = newKeyPair.publicKey();
        vcrypto::VirgilByteArray privateKey = newKeyPair.privateKey();
        vsdk::Credentials userCredentials(privateKey, virgil::crypto::str2bytes(kPrivateKeyPassword));

        vsdk::dto::ValidatedIdentity validatedIdentity1(
            vsdk::dto::Identity(obfuscatorIdentityValue, obfuscatorIdentityType), validationToken1);

        vsdk::ServicesHub servicesHub(virgilAccessToken);
        vsdk::models::CardModel card = servicesHub.card().create(validatedIdentity1, publicKey, userCredentials);

        std::cout << "A Private Virgil Card:" << std::endl;
        std::cout << vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(card) << std::endl;

        std::cout << "4. Revoke the Private Virgil Card\n";
        std::cout << "Revoke the Private Virgil Card" << std::endl;

        std::string validationToken2 =
            vsdk::util::generate_validation_token(obfuscatorIdentityValue, obfuscatorIdentityType, appCredentials);

        vsdk::dto::ValidatedIdentity validatedIdentity2(
            vsdk::dto::Identity(obfuscatorIdentityValue, obfuscatorIdentityType), validationToken2);

        servicesHub.card().revoke(card.getId(), validatedIdentity2, userCredentials);

    } catch (std::exception& exception) {
        std::cerr << exception.what() << std::endl;
        return 1;
    }

    return 0;
}
