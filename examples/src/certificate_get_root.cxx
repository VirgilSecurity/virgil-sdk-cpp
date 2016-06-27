/**
 * Copyright (C) 2016 Virgil Security Inc.
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

static vcrypto::VirgilByteArray loadFile(const std::string & file);

int main(int argc, char** argv) {
    try {
        // Configuration section
        const std::string pathVirgilAccessToken("virgil_access_token.txt");
        
        // Load Access token
        const std::string virgilAccessToken(vcrypto::bytes2str(loadFile(pathVirgilAccessToken)));
        
        // Prepare Sirvices Hub
        vsdk::ServicesHub servicesHub(virgilAccessToken);

        std::cout << "Get the root certificate" << std::endl;
        auto rootCertificate(servicesHub.certificate().pullRootCertificate());
        
        std::cout << "The Virgil Root Certificate:" << std::endl
        << vsdk::io::Marshaller<vsdk::models::CertificateModel>::toJson<4>(rootCertificate)
        << std::endl << std::endl;
        
    } catch (std::exception& exception) {
        std::cerr << exception.what();
        return 1;
    }
    
    return 0;
}

static vcrypto::VirgilByteArray loadFile(const std::string & file) {
    std::ifstream ifs(file, std::ios::in | std::ios::binary);
    if (!ifs) throw std::runtime_error("can not read file: " + file);

    vcrypto::VirgilByteArray ba;
    std::copy(std::istreambuf_iterator<char>(ifs),
              std::istreambuf_iterator<char>(),
              std::back_inserter(ba));

    return ba;
}
