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

static vsdk::dto::ValidatedIdentity generateValidatedIdentity(const vsdk::dto::Identity& obfuscatedIdentity,
                                                              const vsdk::Credentials& appCredentials);

int main(int argc, char** argv) {
    try {
        std::cout << "1. Obfuscate identity" << std::endl;
        std::string userEmail = "bob@mailinator.com";
        std::string obfuscatorIdentityValue = vsdk::util::obfuscate(userEmail, "salt");
        std::string obfuscatorIdentityType = "obfuscated-email";
        vsdk::dto::Identity obfuscatedIdentity(obfuscatorIdentityValue, obfuscatorIdentityType);

        std::cout << "2. Create a Private Virgil Card" << std::endl;
        std::string pathVirgilAccessToken = "virgil_access_token.txt";
        std::ifstream inVirgilAccessTokenFile(pathVirgilAccessToken, std::ios::in | std::ios::binary);
        if (!inVirgilAccessTokenFile) {
            throw std::runtime_error("can not read file: " + pathVirgilAccessToken);
        }
        std::string virgilAccessToken((std::istreambuf_iterator<char>(inVirgilAccessTokenFile)),
                                      std::istreambuf_iterator<char>());

        std::string kPrivateKeyPassword = "qwerty";
        vcrypto::VirgilKeyPair keyPair(vcrypto::str2bytes(kPrivateKeyPassword));
        vcrypto::VirgilByteArray userPublicKey = keyPair.publicKey();
        vcrypto::VirgilByteArray userPrivateKey = keyPair.privateKey();
        vsdk::Credentials userCredentials(userPrivateKey, virgil::crypto::str2bytes(kPrivateKeyPassword));

        std::cout << "2.1 Generation Validation Token" << std::endl;
        std::string pathAppPrivateKey = "application_keys/private.key";
        std::ifstream inAppPrivateKeyFile(pathAppPrivateKey, std::ios::in | std::ios::binary);
        if (!inAppPrivateKeyFile) {
            throw std::runtime_error("can not read private key: " + pathAppPrivateKey);
        }
        vcrypto::VirgilByteArray appPrivateKeyByteArray;
        std::copy(std::istreambuf_iterator<char>(inAppPrivateKeyFile), std::istreambuf_iterator<char>(),
                  std::back_inserter(appPrivateKeyByteArray));

        std::string kApplicationPrivateKeyPassword = "<APPLICATION_PRIVATE_KEY_PASSWORD>";
        vsdk::Credentials appCredentials(appPrivateKeyByteArray,
                                         virgil::crypto::str2bytes(kApplicationPrivateKeyPassword));

        vsdk::ServicesHub servicesHub(virgilAccessToken);
        vsdk::models::CardModel privateCard = servicesHub.card().create(
            generateValidatedIdentity(obfuscatedIdentity, appCredentials), userPublicKey, userCredentials);

        std::cout << "A Private Virgil Card:" << std::endl;
        std::cout << vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(privateCard) << std::endl;

        std::cout << "3. Search for a Private Virgil Card" << std::endl;
        std::vector<vsdk::models::CardModel> foundPrivateCard =
            servicesHub.card().search(obfuscatedIdentity.getValue(), obfuscatedIdentity.getType());

        std::cout << "Found a Private Virgil Card:" << std::endl;
        std::cout << vsdk::io::cardsToJson(foundPrivateCard, 4) << std::endl;

        std::cout << "4. Get a Public Key" << std::endl;
        std::string publicKeyId = privateCard.getPublicKey().getId();
        vsdk::models::PublicKeyModel foundPublicKey = servicesHub.publicKey().get(publicKeyId);

        std::cout << "Found a Public Key:" << std::endl;
        std::cout << vsdk::io::Marshaller<vsdk::models::PublicKeyModel>::toJson<4>(foundPublicKey) << std::endl;

        std::cout << "5. Stash a Private Key" << std::endl;
        servicesHub.privateKey().add(privateCard.getId(), userCredentials);

        std::cout << "6. Get a Private Key:" << std::endl;
        vsdk::models::PrivateKeyModel privateKey = servicesHub.privateKey().get(
            privateCard.getId(), generateValidatedIdentity(obfuscatedIdentity, appCredentials));

        std::cout << vsdk::io::Marshaller<vsdk::models::PrivateKeyModel>::toJson<4>(privateKey) << std::endl;

        std::cout << "7. Destroy a Private Key" << std::endl;
        servicesHub.privateKey().del(privateCard.getId(), userCredentials);

        std::cout << "8. Revoke the Private Virgil Card\n";
        servicesHub.card().revoke(privateCard.getId(), generateValidatedIdentity(obfuscatedIdentity, appCredentials),
                                  userCredentials);

    } catch (std::exception& exception) {
        std::cerr << exception.what();
        return 1;
    }

    return 0;
}

vsdk::dto::ValidatedIdentity generateValidatedIdentity(const vsdk::dto::Identity& obfuscatedIdentity,
                                                       const vsdk::Credentials& appCredentials) {

    std::string validationToken = vsdk::util::generate_validation_token(obfuscatedIdentity.getValue(),
                                                                        obfuscatedIdentity.getType(), appCredentials);

    return vsdk::dto::ValidatedIdentity(obfuscatedIdentity, validationToken);
}
