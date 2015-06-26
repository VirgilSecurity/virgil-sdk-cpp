/**
 * Copyright (C) 2014 Virgil Security Inc.
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

#include <cstddef>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>
#include <stdexcept>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/pki/model/Account.h>
using virgil::pki::model::Account;
#include <virgil/pki/model/PublicKey.h>
using virgil::pki::model::PublicKey;
#include <virgil/pki/io/marshaller.h>
using virgil::pki::io::marshaller;
#include <virgil/pki/http/ConnectionBase.h>
using virgil::pki::http::ConnectionBase;
#include <virgil/pki/client/PublicKeyClientBase.h>
using virgil::pki::client::PublicKeyClientBase;

static const std::string VIRGIL_PKI_URL_BASE = "https://pki-stg.virgilsecurity.com/v1/";
static const std::string VIRGIL_PKI_APP_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
static const std::string USER_ID = "test.virgilsecurity@mailinator.com";

int main() {
    try {
        std::cout << "Get user ("<< USER_ID << ") information from the Virgil PKI service..." << std::endl;
        PublicKeyClientBase publicKeyClient(
                std::make_shared<ConnectionBase>(VIRGIL_PKI_APP_TOKEN, VIRGIL_PKI_URL_BASE));
        std::vector<Account> accounts = publicKeyClient.search(USER_ID);
        if (accounts.empty() || accounts.front().publicKeys().empty()) {
            throw std::runtime_error(std::string("User with id: ") + USER_ID + " not found.");
        }
        PublicKey publicKey = accounts.front().publicKeys().front();

        std::cout << "Prepare output file: virgil_public.key..." << std::endl;
        std::ofstream outFile("virgil_public.key", std::ios::out | std::ios::binary);
        if (!outFile.good()) {
            throw std::runtime_error("can not write file: virgil_public.key");
        }

        std::cout << "Store virgil public key to the output file..." << std::endl;
        std::string publicKeyData = marshaller<PublicKey>::toJson(publicKey);
        std::copy(publicKeyData.begin(), publicKeyData.end(), std::ostreambuf_iterator<char>(outFile));
    } catch (std::exception& exception) {
        std::cerr << "Error: " << exception.what() << std::endl;
    }
    return 0;
}
