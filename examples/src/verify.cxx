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
#include <vector>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilStreamSigner.h>
#include <virgil/crypto/stream/VirgilStreamDataSource.h>

#include <virgil/sdk/ServicesHub.h>
#include <virgil/sdk/ServiceUri.h>

namespace vsdk = virgil::sdk;
namespace vcrypto = virgil::crypto;

const std::string VIRGIL_ACCESS_TOKEN =
    "eyJpZCI6IjFkNzgzNTA1LTk1NGMtNDJhZC1hZThjLWQyOGFiYmN"
    "hMGM1NyIsImFwcGxpY2F0aW9uX2NhcmRfaWQiOiIwNGYyY2Y2NS1iZDY2LTQ3N2EtOGFiZi1hMDAyYWY4Yj"
    "dmZWYiLCJ0dGwiOi0xLCJjdGwiOi0xLCJwcm9sb25nIjowfQ==.MIGZMA0GCWCGSAFlAwQCAgUABIGHMIGE"
    "AkAV1PHR3JaDsZBCl+6r/N5R5dATW9tcS4c44SwNeTQkHfEAlNboLpBBAwUtGhQbadRd4N4gxgm31sajEOJ"
    "IYiGIAkADCz+MncOO74UVEEot5NEaCtvWT7fIW9WaF6JdH47Z7kTp0gAnq67cPbS0NDUyovAqILjmOmg1zA"
    "L8A4+ii+zd";

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << std::string("USAGE: ") + argv[0] + " <user_email>"
                  << "\n";
        return 1;
    }

    try {
        std::string userEmail = argv[1];

        std::cout << "Prepare input file: test.txt..."
                  << "\n";
        std::ifstream inFile("test.txt", std::ios::in | std::ios::binary);
        if (!inFile) {
            throw std::runtime_error("can not read file: test.txt");
        }
        vcrypto::stream::VirgilStreamDataSource dataSource(inFile);

        std::cout << "Read virgil sign..."
                  << "\n";
        std::ifstream signFile("test.txt.sign", std::ios::in | std::ios::binary);
        if (!signFile) {
            throw std::runtime_error("can not read sign: test.txt.sign");
        }
        vcrypto::VirgilByteArray sign;
        std::copy(std::istreambuf_iterator<char>(signFile), std::istreambuf_iterator<char>(), std::back_inserter(sign));

        std::cout << "Get signer (" << userEmail << ") public key from the Virgil PKI service..."
                  << "\n";
        vsdk::ServicesHub virgilHub(VIRGIL_ACCESS_TOKEN);
        virgilHub.loadServicesCard();

        vsdk::model::Identity identity(userEmail, vsdk::model::IdentityType::Email);
        std::vector<vsdk::model::VirgilCard> recipientCards = virgilHub.cards().search(identity);
        vsdk::model::PublicKey recipientPublicKey = recipientCards.at(0).getPublicKey();

        vcrypto::VirgilStreamSigner signer;
        std::cout << "Verify data..."
                  << "\n";
        bool verified = signer.verify(dataSource, sign, recipientPublicKey.getKeyBytes());
        std::cout << "Data is " << (verified ? "" : "not ") << "verified!"
                  << "\n";

    } catch (std::exception& exception) {
        std::cerr << exception.what() << "\n";
        return 1;
    }

    return 0;
}
