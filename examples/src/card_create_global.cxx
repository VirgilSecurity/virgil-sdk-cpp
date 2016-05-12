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

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

int main(int argc, char** argv) {
    try {
        std::cout << "1. Create a Global Virgil Card" << std::endl;
        std::string userEmail;
        std::cout << "Enter email:" << std::endl;
        std::cin >> userEmail;

        std::string pathVirgilAccessToken = "virgil_access_token.txt";
        std::ifstream inVirgilAccessTokenFile(pathVirgilAccessToken, std::ios::in | std::ios::binary);
        if (!inVirgilAccessTokenFile) {
            throw std::runtime_error("can not read file: " + pathVirgilAccessToken);
        }
        std::string virgilAccessToken((std::istreambuf_iterator<char>(inVirgilAccessTokenFile)),
                                      std::istreambuf_iterator<char>());

        vsdk::ServicesHub servicesHub(virgilAccessToken);
        std::cout << "1.1 Get Validated Identity from Identity Service" << std::endl;

        std::cout << "The email with confirmation code has been sent to your email address. Please check it!"
                  << std::endl;
        std::string actionId = servicesHub.identity().verify(userEmail, vsdk::dto::VerifiableIdentityType::Email);
        std::string confirmationCode;

        std::cout << "Enter Code:" << std::endl;
        std::cin >> confirmationCode;
        vsdk::dto::ValidatedIdentity validatedIdentity =
            servicesHub.identity().confirm(actionId, confirmationCode, 3600, 3);

        std::string kPrivateKeyPassword = "qwerty";
        vcrypto::VirgilKeyPair keyPair(vcrypto::str2bytes(kPrivateKeyPassword));
        vcrypto::VirgilByteArray userPublicKey = keyPair.publicKey();
        vcrypto::VirgilByteArray userPrivateKey = keyPair.privateKey();
        vsdk::Credentials userCredentials(userPrivateKey, virgil::crypto::str2bytes(kPrivateKeyPassword));

        vsdk::models::CardModel globalCard =
            servicesHub.card().create(validatedIdentity, userPublicKey, userCredentials);
        std::cout << "A Global Virgil Card:" << std::endl;
        std::cout << vsdk::io::Marshaller<vsdk::models::CardModel>::toJson<4>(globalCard) << std::endl;

        std::cout << "3. Search for a Global Virgil Card" << std::endl;
        std::vector<vsdk::models::CardModel> foundGlobalCard =
            servicesHub.card().searchGlobal(userEmail, vsdk::dto::IdentityType::Email);

        std::cout << "Found a Global Virgil Card:" << std::endl;
        std::cout << virgil::sdk::io::cardsToJson(foundGlobalCard, 4) << std::endl;

        std::cout << "4. Get a Public Key" << std::endl;
        std::string publicKeyId = globalCard.getPublicKey().getId();
        vsdk::models::PublicKeyModel foundPublicKey = servicesHub.publicKey().get(publicKeyId);

        std::cout << "Found a Public Key:" << std::endl;
        std::cout << vsdk::io::Marshaller<vsdk::models::PublicKeyModel>::toJson<4>(foundPublicKey) << std::endl;

        std::cout << "5. Stash a Private Key" << std::endl;
        servicesHub.privateKey().add(globalCard.getId(), userCredentials);

        std::cout << "6. Get a Private Key:" << std::endl;
        vsdk::models::PrivateKeyModel privateKey = servicesHub.privateKey().get(globalCard.getId(), validatedIdentity);

        std::cout << vsdk::io::Marshaller<vsdk::models::PrivateKeyModel>::toJson<4>(privateKey) << std::endl;

        std::cout << "7. Destroy a Private Key" << std::endl;
        servicesHub.privateKey().del(globalCard.getId(), userCredentials);

        std::cout << "8. Revoke the Private Virgil Card\n";
        servicesHub.card().revoke(globalCard.getId(), validatedIdentity, userCredentials);

    } catch (std::exception& exception) {
        std::cerr << exception.what();
        return 1;
    }

    return 0;
}
