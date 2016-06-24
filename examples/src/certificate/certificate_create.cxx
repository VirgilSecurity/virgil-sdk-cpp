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

static vsdk::dto::ValidatedIdentity generateValidatedIdentity(const vsdk::dto::Identity& identity,
                                                              const vsdk::Credentials& appCredentials);

int main(int argc, char** argv) {
    try {
        const std::string identityStr("new-card-test-identity");
        const std::string identityType("test-identity-type");
        vsdk::dto::Identity identity(identityStr, identityType);
        
        std::cout << "1. Create a Virgil Certificate" << std::endl;
        
        const std::string pathVirgilAccessToken("virgil_access_token.txt");
        std::ifstream inVirgilAccessTokenFile(pathVirgilAccessToken,
                                              std::ios::in | std::ios::binary);
        if (!inVirgilAccessTokenFile) {
            throw std::runtime_error("can not read file: " + pathVirgilAccessToken);
        }
        const std::string virgilAccessToken((std::istreambuf_iterator<char>(inVirgilAccessTokenFile)),
                                      std::istreambuf_iterator<char>());
        
        const std::string kPrivateKeyPassword("qwerty");
        const vcrypto::VirgilKeyPair keyPair(vcrypto::str2bytes(kPrivateKeyPassword));
        const vcrypto::VirgilByteArray userPublicKey(keyPair.publicKey());
        const vcrypto::VirgilByteArray userPrivateKey(keyPair.privateKey());
        const vsdk::Credentials userCredentials(userPrivateKey,
                                                virgil::crypto::str2bytes(kPrivateKeyPassword));
        
        
        std::cout << "1.1 Generation Validation Token" << std::endl;
        
        const std::string pathAppPrivateKey("application_keys/private.key");
        std::ifstream inAppPrivateKeyFile(pathAppPrivateKey,
                                          std::ios::in | std::ios::binary);
        if (!inAppPrivateKeyFile) {
            throw std::runtime_error("can not read private key: " + pathAppPrivateKey);
        }
        vcrypto::VirgilByteArray appPrivateKeyByteArray;
        std::copy(std::istreambuf_iterator<char>(inAppPrivateKeyFile),
                  std::istreambuf_iterator<char>(),
                  std::back_inserter(appPrivateKeyByteArray));
        
        const std::string kApplicationPrivateKeyPassword("qweASD123");
        vsdk::Credentials appCredentials(appPrivateKeyByteArray,
                                         virgil::crypto::str2bytes(kApplicationPrivateKeyPassword));
        
        
        vsdk::ServicesHub servicesHub(virgilAccessToken);
        vsdk::dto::ValidatedIdentity validatedIdentity(generateValidatedIdentity(identity, appCredentials));
        
        vsdk::models::CertificateModel certificate(servicesHub
                                            .certificate()
                                            .create(validatedIdentity,
                                                    userPublicKey,
                                                    userCredentials));
        
        std::cout << "A Virgil Certificate:" << std::endl;
        std::cout << vsdk::io::Marshaller<vsdk::models::CertificateModel>::toJson<4>(certificate) << std::endl;
    } catch (std::exception& exception) {
        std::cerr << exception.what();
        return 1;
    }
    
    return 0;
}

vsdk::dto::ValidatedIdentity generateValidatedIdentity(const vsdk::dto::Identity& identity,
                                                       const vsdk::Credentials& appCredentials) {
    
    std::string validationToken = vsdk::util::generate_validation_token(identity.getValue(),
                                                                        identity.getType(), appCredentials);
    
    return vsdk::dto::ValidatedIdentity(identity, validationToken);
}
