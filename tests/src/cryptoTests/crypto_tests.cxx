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

#include <fstream>
#include <sstream>

#include <catch.hpp>
#include <helpers.h>

#include <virgil/sdk/Common.h>
#include <virgil/sdk/crypto/Crypto.h>

using virgil::sdk::crypto::Crypto;
using virgil::sdk::VirgilByteArrayUtils;
using virgil::sdk::test::Utils;

TEST_CASE("testED001_EncryptRandomData_SingleCorrectKey_ShouldDecrypt", "[crypto]") {
    auto data = Utils::generateRandomData(100);
    Crypto crypto;

    auto keyPair = crypto.generateKeyPair();

    auto encryptedData = crypto.encrypt(data, { keyPair.publicKey() });

    auto decryptedData = crypto.decrypt(encryptedData, keyPair.privateKey());

    REQUIRE(data == decryptedData);
}

TEST_CASE("testED002_EncryptRandomData_SingleIncorrectKey_ShouldNotDecrypt", "[crypto]") {
    auto data = Utils::generateRandomData(100);
    Crypto crypto;

    auto keyPair = crypto.generateKeyPair();
    auto wrongKeyPair = crypto.generateKeyPair();

    auto encryptedData = crypto.encrypt(data, { keyPair.publicKey() });

    auto errorWasThrown = false;
    try {
        auto decryptedData = crypto.decrypt(encryptedData, wrongKeyPair.privateKey());
    }
    catch (...) {
        errorWasThrown = true;
    }

    REQUIRE(errorWasThrown);
}

TEST_CASE("testED003_EncryptRandomData_TwoCorrectKeys_ShouldDecrypt", "[crypto]") {
    auto data = Utils::generateRandomData(100);
    Crypto crypto;

    auto keyPair1 = crypto.generateKeyPair();
    auto keyPair2 = crypto.generateKeyPair();

    auto encryptedData = crypto.encrypt(data, { keyPair1.publicKey(), keyPair2.publicKey() });

    auto decryptedData1 = crypto.decrypt(encryptedData, keyPair1.privateKey());
    auto decryptedData2 = crypto.decrypt(encryptedData, keyPair2.privateKey());

    REQUIRE(data == decryptedData1);
    REQUIRE(data == decryptedData2);
}

TEST_CASE("testES001_EncryptRandomDataStream_SingleCorrectKey_ShouldDecrypt", "[crypto]") {
    Crypto crypto;
    auto keyPair = crypto.generateKeyPair();

    auto data = Utils::generateRandomData(100);

    auto dataStr = VirgilByteArrayUtils::bytesToHex(data);
    std::istringstream inputStreamForEncryption(dataStr);
    std::ostringstream outputStreamForEncryption;

    crypto.encrypt(inputStreamForEncryption, outputStreamForEncryption, { keyPair.publicKey() });

    auto encryptedStr = outputStreamForEncryption.str();

    std::istringstream inputStreamForDecryption(encryptedStr);
    std::ostringstream outputStreamForDecryption;

    crypto.decrypt(inputStreamForDecryption, outputStreamForDecryption, keyPair.privateKey());

    auto decryptedStr = outputStreamForDecryption.str();

    auto decryptedData = VirgilByteArrayUtils::hexToBytes(decryptedStr);

    REQUIRE(data == decryptedData);
}

TEST_CASE("testES002_EncryptRandomDataStream_SingleIncorrectKey_ShouldNotDecrypt", "[crypto]") {
    Crypto crypto;
    auto keyPair = crypto.generateKeyPair();
    auto wrongKeyPair = crypto.generateKeyPair();

    auto data = Utils::generateRandomData(100);

    auto dataStr = VirgilByteArrayUtils::bytesToHex(data);
    std::istringstream inputStreamForEncryption(dataStr);
    std::ostringstream outputStreamForEncryption;

    crypto.encrypt(inputStreamForEncryption, outputStreamForEncryption, { keyPair.publicKey() });

    auto encryptedStr = outputStreamForEncryption.str();

    std::istringstream inputStreamForDecryption(encryptedStr);
    std::ostringstream outputStreamForDecryption;

    auto errorWasThrown = false;
    try {
        crypto.decrypt(inputStreamForDecryption, outputStreamForDecryption, wrongKeyPair.privateKey());
    }
    catch (...) {
        errorWasThrown = true;
    }

    REQUIRE(errorWasThrown);
}

TEST_CASE("testES003_EncryptRandomDataStream_TwoCorrectKeys_ShouldDecrypt", "[crypto]") {
    Crypto crypto;
    auto keyPair1 = crypto.generateKeyPair();
    auto keyPair2 = crypto.generateKeyPair();

    auto data = Utils::generateRandomData(100);

    auto dataStr = VirgilByteArrayUtils::bytesToHex(data);
    std::istringstream inputStreamForEncryption(dataStr);
    std::ostringstream outputStreamForEncryption;

    crypto.encrypt(inputStreamForEncryption, outputStreamForEncryption, { keyPair1.publicKey(), keyPair2.publicKey() });

    auto encryptedStr = outputStreamForEncryption.str();

    std::istringstream inputStreamForDecryption1(encryptedStr);
    std::ostringstream outputStreamForDecryption1;

    std::istringstream inputStreamForDecryption2(encryptedStr);
    std::ostringstream outputStreamForDecryption2;

    crypto.decrypt(inputStreamForDecryption1, outputStreamForDecryption1, keyPair1.privateKey());
    crypto.decrypt(inputStreamForDecryption2, outputStreamForDecryption2, keyPair2.privateKey());

    auto decryptedStr1 = outputStreamForDecryption1.str();
    auto decryptedStr2 = outputStreamForDecryption2.str();

    auto decryptedData1 = VirgilByteArrayUtils::hexToBytes(decryptedStr1);
    auto decryptedData2 = VirgilByteArrayUtils::hexToBytes(decryptedStr2);

    REQUIRE(data == decryptedData1);
    REQUIRE(data == decryptedData2);
}

TEST_CASE("testES004_EncryptFileDataStream_SingleCorrectKey_ShouldDecrypt", "[crypto]") {
    Crypto crypto;
    auto keyPair = crypto.generateKeyPair();

    std::ifstream inputStreamForEncryption("testData.txt");
    std::ostringstream outputStreamForEncryption;

    crypto.encrypt(inputStreamForEncryption, outputStreamForEncryption, { keyPair.publicKey() });

    auto encryptedStr = outputStreamForEncryption.str();

    std::istringstream inputStreamForDecryption(encryptedStr);
    std::ostringstream outputStreamForDecryption;

    crypto.decrypt(inputStreamForDecryption, outputStreamForDecryption, keyPair.privateKey());

    auto decryptedStr = outputStreamForDecryption.str();

    REQUIRE(decryptedStr == "Hello, Bob!\n");
}

TEST_CASE("testSD001_SignRandomData_CorrectKeys_ShouldValidate", "[crypto]") {
    auto crypto = Crypto();
    auto keyPair = crypto.generateKeyPair();

    auto data = Utils::generateRandomData(100);

    auto signature = crypto.generateSignature(data, keyPair.privateKey());

    REQUIRE(crypto.verify(data, signature, keyPair.publicKey()));
}

TEST_CASE("testSD002_SignRandomData_IncorrectKeys_ShouldNotValidate", "[crypto]") {
    Crypto crypto;
    auto keyPair = crypto.generateKeyPair();
    auto wrongKeyPair = crypto.generateKeyPair();

    auto data = Utils::generateRandomData(100);

    auto signature = crypto.generateSignature(data, keyPair.privateKey());

    REQUIRE(!crypto.verify(data, signature, wrongKeyPair.publicKey()));
}

TEST_CASE("testESD001_SignAndEncryptRandomData_CorrectKeys_ShouldDecryptValidate", "[crypto]") {
    Crypto crypto;
    auto senderKeyPair = crypto.generateKeyPair();
    auto receiverKeyPair = crypto.generateKeyPair();

    auto data = Utils::generateRandomData(100);

    auto signedAndEncryptedData = crypto.signThenEncrypt(data, senderKeyPair.privateKey(), { receiverKeyPair.publicKey() });

    auto decryptedAndVerifiedData = crypto.decryptThenVerify(signedAndEncryptedData, receiverKeyPair.privateKey(), senderKeyPair.publicKey());

    REQUIRE(data == decryptedAndVerifiedData);
}
