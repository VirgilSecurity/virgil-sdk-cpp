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

#ifndef HELPERS_H
#define HELPERS_H

#include <string>
#include <vector>

#include <json.hpp>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/privatekeys/client/Credentials.h>
#include <virgil/sdk/privatekeys/model/ContainerType.h>
#include <virgil/sdk/privatekeys/util/JsonKey.h>

constexpr char VIRGIL_APP_TOKEN[] = "45fd8a505f50243fa8400594ba0b2b29";
constexpr char USER_PUBLIC_KEY_ID[] = "f437d5b1-90e3-ec3b-3744-d9e23a892c41";
constexpr char USER_EMAIL[] = "test.virgilsecurity@mailinator.com";
constexpr char CONTAINER_PASSWORD[] = "123456789";
constexpr char CONFIRMATION_CODE[] = "A3F4S3";
constexpr char UUID[] = "57e0a766-28ef-355e-7ca2-d8a2dcf23fc4";

inline virgil::crypto::VirgilByteArray expectedUserPrivateKeyData() {
    std::string privateKeys =
        "-----BEGIN PRIVATE KEY-----"
        "MIHsAgEAMBQGByqGSM49AgEGCSskAwMCCAEBDQSB0DCBzQIBAQRAYfsONejc+RyL"
        "TEa6TXizoAggmLPjQR6ywkGAr2ua5C/faveunixw1CoaBmkBxUomRnQeyvDIW1at"
        "04vexApRAaGBhQOBggAEmievpkVDuymIV7+MtOmwq/4qDxYE/18HcCvmmosOCcOt"
        "gs2hVzH4cLnoaFt8Wz0qERjffVqnfkq14Lx6SwPOi5ZLJo/Jzk8Z89LVbZWAyGgg"
        "n7pCoQeg9sPZHczFBy0RZEeuuJq0bQYEgx00ZqZ2ecBUxJFmcQkUDI9nbVQthYc="
        "-----END PRIVATE KEY-----";
    return virgil::crypto::str2bytes(privateKeys);
}

inline virgil::sdk::privatekeys::client::Credentials expectedCredentials() {
    return virgil::sdk::privatekeys::client::Credentials(USER_PUBLIC_KEY_ID, expectedUserPrivateKeyData());
}

#endif /* HELPERS_H */
