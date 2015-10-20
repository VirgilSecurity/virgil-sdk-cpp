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

#include <virgil/sdk/keys/io/Marshaller.h>
#include <virgil/sdk/keys/model/PublicKey.h>

#include <virgil/sdk/privatekeys/client/PrivateKeysClient.h>
#include <virgil/sdk/privatekeys/model/PrivateKey.h>
#include <virgil/sdk/privatekeys/model/UserData.h>

using virgil::sdk::keys::io::Marshaller;
using virgil::sdk::keys::model::PublicKey;

using virgil::sdk::privatekeys::model::PrivateKey;
using virgil::sdk::privatekeys::client::PrivateKeysClient;
using virgil::sdk::privatekeys::model::UserData;

const std::string VIRGIL_PK_URL_BASE = "https://keys-private.virgilsecurity.com";
const std::string VIRGIL_APP_TOKEN = "45fd8a505f50243fa8400594ba0b2b29";
const std::string USER_EMAIL = "test.virgilsecurity@mailinator.com";
const std::string CONTAINER_PASSWORD = "123456789";

int main() {
    try {
        std::cout << "Read virgil public key..." << std::endl;
        std::ifstream publicKeyFile("virgil_public.key", std::ios::in | std::ios::binary);
        if (!publicKeyFile.good()) {
            throw std::runtime_error("can not read virgil public key: virgil_public.key");
        }
        std::string publicKeyData;
        std::copy(std::istreambuf_iterator<char>(publicKeyFile), std::istreambuf_iterator<char>(),
            std::back_inserter(publicKeyData));

        PublicKey publicKey = Marshaller<PublicKey>::fromJson(publicKeyData);

        std::cout << "Create Private Keys Service HTTP Client." << std::endl;
        PrivateKeysClient privateKeysClient(VIRGIL_APP_TOKEN, VIRGIL_PK_URL_BASE);

        std::cout << "Authenticate session..." << std::endl;
        UserData userData = UserData::email(USER_EMAIL);
        privateKeysClient.authenticate(userData, CONTAINER_PASSWORD);

        std::cout << "Call the Private Key service to get a Private Key instance." << std::endl;
        PrivateKey privateKey = privateKeysClient.privateKey().get(publicKey.publicKeyId());

        std::cout << "Private Key instance successfully fetched from the Private Keys service." << std::endl;
        std::cout << "Public key id: " << privateKey.publicKeyId() << std::endl;
        std::cout << "Private key: " << std::endl;
        std::vector<unsigned char> key = privateKey.key();
        std::copy(key.begin(), key.end(), std::ostreambuf_iterator<char>(std::cout));
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
    }

    return 0;
}
