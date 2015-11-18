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
constexpr char VIRGIL_AUTHENTICATION_TOKEN[] = "dbbbe6a906aa4d567531827beb66a2aadbbbe6a906aa4d567531827beb66a2aa";

// dbb -> 666  - new
constexpr char NEW_VIRGIL_AUTHENTICATION_TOKEN[] = "666be6a906aa4d567531827beb66a2aadbbbe6a906aa4d567531827beb66a2aa";

constexpr char USER_PUBLIC_KEY_ID[] = "f437d5b1-90e3-ec3b-3744-d9e23a892c41";
constexpr char USER_EMAIL[] = "test.virgilsecurity@mailinator.com";
constexpr char USER_PASSWORD[] = "123456789";
constexpr char CONTAINER_PASSWORD[] = "123456789";
constexpr char CONFIRMATION_CODE[] = "A3F4S3";

constexpr char PASS_PRIVATE_KEY[] = "666";

inline virgil::crypto::VirgilByteArray expectedPrivateKeyDataWithPass() {
    std::string privateKeys =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----"
            "MIIBMTA0BgoqhkiG9w0BDAEDMCYEIISrD85zdxtAmgPkqBmIWraKTCuMwMd23B7j"
            "ncySx7Z9AgIgAASB+ETiRAFVxk5kBlJMd2+N1tf89tCcr+rkBhJV2ux02lBluOhG"
            "jbX/ydiRSVPpobO+TH37X90Ypae74cXfSL38lBy0mshzIXOEGujAQ1mbxOPjyGJc"
            "zQVMdo8/2dQAIVqG0d1C0EHeHAsXsI+yqn9hWtUxYa+qUT/TICBvzq+71i7elAbb"
            "YO/B+At+d/IjlWWEpWpaFz5rOoWUFLjb5jkVEhF6vA4RYrm0907pyNzbi5i2Tiiy"
            "3bC2R8wCvSIxR66L+ZXOO5Qfx0YG3dxwLnfEmII8mKkxySPO0rEaUcB6d7CPwgm0"
            "UyTZ7nK48dzkauSG/6DjJH/SCKib"
            "-----END ENCRYPTED PRIVATE KEY-----";
    return virgil::crypto::str2bytes(privateKeys);
}

inline virgil::crypto::VirgilByteArray expectedPrivateKeyData() {
    std::string privateKeys =
            "-----BEGIN EC PRIVATE KEY-----"
            "MIHbAgEBBEEAhbT3jHL8eU7QAuHplFlUzXssLtBRTLb5qT/eXVvq/Xe1+2PkzjXe"
            "M+556naXKA/Rfk6AKYKu6a4ML+2DJ16xhKALBgkrJAMDAggBAQ2hgYUDgYIABHev"
            "+jQIyCA/CZ71t57sJDBUEO1QTpsPhJxoKbWiVkF+kzBcNjFnRo/DvQ4cVEalJz+Z"
            "pzbJ7b9FV3FHbDaFFW9sSlAjOZSCsSb+oYE1EREtITHPnEdAq8haOBa/oN1IlzZD"
            "eqEq3uryZb25NeEx94UoGprKPBetMyWPD8v+L6RF"
            "-----END EC PRIVATE KEY-----";
   return virgil::crypto::str2bytes(privateKeys);
}

inline virgil::sdk::privatekeys::client::Credentials expectedCredentialsPubIdKey() {
    return virgil::sdk::privatekeys::client::Credentials(USER_PUBLIC_KEY_ID, expectedPrivateKeyData());
}

inline virgil::sdk::privatekeys::client::Credentials expectedCredentialsPubIdKeyPass() {
    return virgil::sdk::privatekeys::client::Credentials(USER_PUBLIC_KEY_ID, 
            expectedPrivateKeyDataWithPass(),
            PASS_PRIVATE_KEY);
}

#endif /* HELPERS_H */
