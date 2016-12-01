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


#include <catch.hpp>
#include <nlohman/json.hpp>

#include <fstream>

#include <virgil/sdk/Common.h>
#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/sdk/client/models/requests/CreateCardRequest.h>

using virgil::sdk::VirgilBase64;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::VirgilByteArrayUtils;
using virgil::sdk::crypto::keys::PrivateKey;
using virgil::sdk::client::models::requests::CreateCardRequest;

using json = nlohmann::json;

TEST_CASE("test001_CheckNumberOfTestsInJSON", "[compatibility]") {
    std::ifstream input("sdk_compatibility_data.json");

    std::string str((std::istreambuf_iterator<char>(input)),
                    std::istreambuf_iterator<char>());

    auto j = json::parse(str);

    REQUIRE(j.size() == 6);
}

TEST_CASE("test002_DecryptFromSingleRecipient_ShouldDecrypt", "[compatibility]") {
    auto crypto = Crypto();

    std::ifstream input("sdk_compatibility_data.json");

    std::string str((std::istreambuf_iterator<char>(input)),
                    std::istreambuf_iterator<char>());

    auto j = json::parse(str);

    json dict = j["encrypt_single_recipient"];

    std::string privateKeyStr = dict["private_key"];
    auto privateKey = crypto.importPrivateKey(VirgilBase64::decode(privateKeyStr));

    std::string originalDataStr = dict["original_data"];

    std::string cipherDataStr = dict["cipher_data"];
    auto cipherData = VirgilBase64::decode(cipherDataStr);

    auto decryptedData = crypto.decrypt(cipherData, privateKey);
    auto decryptedDataStr = VirgilBase64::encode(decryptedData);

    REQUIRE(decryptedDataStr == originalDataStr);
}

TEST_CASE("test003_DecryptFromMultipleRecipients_ShouldDecypt", "[compatibility]") {
    auto crypto = Crypto();

    std::ifstream input("sdk_compatibility_data.json");

    std::string str((std::istreambuf_iterator<char>(input)),
                    std::istreambuf_iterator<char>());

    auto j = json::parse(str);

    json dict = j["encrypt_multiple_recipients"];

    std::vector<PrivateKey> privateKeys;

    std::vector<json> privateKeysJson = dict["private_keys"];

    for (const std::string &privateKeyStr : privateKeysJson) {
        auto privateKeyData = VirgilBase64::decode(privateKeyStr);

        auto privateKey = crypto.importPrivateKey(privateKeyData);

        privateKeys.push_back(std::move(privateKey));
    }

    REQUIRE(privateKeys.size() > 0);

    std::string originalDataStr = dict["original_data"];

    std::string cipherDataStr = dict["cipher_data"];
    auto cipherData = VirgilBase64::decode(cipherDataStr);

    for (auto& privateKey : privateKeys) {
        auto decryptedData = crypto.decrypt(cipherData, privateKey);
        auto decryptedDataStr = VirgilBase64::encode(decryptedData);

        REQUIRE(decryptedDataStr == originalDataStr);
    }
}

TEST_CASE("test004_DecryptThenVerifySingleRecipient_ShouldDecryptAndVerify", "[compatibility]") {
    auto crypto = Crypto();

    std::ifstream input("sdk_compatibility_data.json");

    std::string str((std::istreambuf_iterator<char>(input)),
                    std::istreambuf_iterator<char>());

    auto j = json::parse(str);

    json dict = j["sign_then_encrypt_single_recipient"];

    std::string privateKeyStr = dict["private_key"];
    auto privateKey = crypto.importPrivateKey(VirgilBase64::decode(privateKeyStr));
    auto publicKey = crypto.extractPublicKeyFromPrivateKey(privateKey);

    std::string originalDataStr = dict["original_data"];

    std::string cipherDataStr = dict["cipher_data"];
    auto cipherData = VirgilBase64::decode(cipherDataStr);

    auto decryptedData = crypto.decryptThenVerify(cipherData, privateKey, publicKey);
    auto decryptedDataStr = VirgilBase64::encode(decryptedData);

    REQUIRE(decryptedDataStr == originalDataStr);
}

TEST_CASE("test005_DecryptThenVerifyMultipleRecipients_ShouldDecryptAndVerify", "[compatibility]") {
    auto crypto = Crypto();

    std::ifstream input("sdk_compatibility_data.json");

    std::string str((std::istreambuf_iterator<char>(input)),
                    std::istreambuf_iterator<char>());

    auto j = json::parse(str);

    json dict = j["sign_then_encrypt_multiple_recipients"];

    std::vector<PrivateKey> privateKeys;

    std::vector<json> privateKeysJson = dict["private_keys"];

    for (const std::string &privateKeyStr : privateKeysJson) {
        auto privateKeyData = VirgilBase64::decode(privateKeyStr);

        auto privateKey = crypto.importPrivateKey(privateKeyData);

        privateKeys.push_back(std::move(privateKey));
    }

    REQUIRE(privateKeys.size() > 0);

    std::string originalDataStr = dict["original_data"];

    std::string cipherDataStr = dict["cipher_data"];
    auto cipherData = VirgilBase64::decode(cipherDataStr);

    auto signerPublicKey = crypto.extractPublicKeyFromPrivateKey(privateKeys[0]);

    for (auto& privateKey : privateKeys) {
        auto decryptedData = crypto.decryptThenVerify(cipherData, privateKey, signerPublicKey);
        auto decryptedDataStr = VirgilBase64::encode(decryptedData);

        REQUIRE(decryptedDataStr == originalDataStr);
    }
}

TEST_CASE("test006_GenerateSignature_ShouldBeEqual", "[compatibility]") {
    auto crypto = Crypto();

    std::ifstream input("sdk_compatibility_data.json");

    std::string str((std::istreambuf_iterator<char>(input)),
                    std::istreambuf_iterator<char>());

    auto j = json::parse(str);

    json dict = j["generate_signature"];

    std::string privateKeyStr = dict["private_key"];
    auto privateKey = crypto.importPrivateKey(VirgilBase64::decode(privateKeyStr));

    std::string originalDataStr = dict["original_data"];
    auto originalData = VirgilBase64::decode(originalDataStr);

    auto signature = crypto.generateSignature(originalData, privateKey);
    auto signatureStr = VirgilBase64::encode(signature);

    std::string originalSignatureStr = dict["signature"];

    REQUIRE(signatureStr == originalSignatureStr);
}

TEST_CASE("test007_ExportSignableData_ShouldBeEqual", "[compatibility]") {
    auto crypto = Crypto();

    std::ifstream input("sdk_compatibility_data.json");

    std::string str((std::istreambuf_iterator<char>(input)),
                    std::istreambuf_iterator<char>());

    auto j = json::parse(str);

    json dict = j["export_signable_request"];

    std::string exportedRequest = dict["exported_request"];

    auto request = CreateCardRequest::importFromString(exportedRequest);

    auto fingerprint = crypto.calculateFingerprint(request.snapshot());

    auto creatorPublicKey = crypto.importPublicKey(request.snapshotModel().publicKeyData());

    auto fingerprintHex = fingerprint.hexValue();

    auto signature = request.signatures().at(fingerprintHex);

    auto verified = crypto.verify(fingerprint.value(), signature, creatorPublicKey);
    REQUIRE(verified);
}