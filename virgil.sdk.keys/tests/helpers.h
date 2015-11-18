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

#include <virgil/sdk/keys/model/PublicKey.h>
#include <virgil/sdk/keys/model/UserData.h>

#include <virgil/crypto/foundation/VirgilBase64.h>

inline std::string appToken() {
    return "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
}

inline std::string actionToken() {
    return "57516f1b-f17c-3154-c91e-edb86c514c5d";
}

inline std::string confirmationCode() {
    return "A3F4S3";
}

inline std::vector<std::string> confirmationCodes() {
    return {"A4D2B6","B4G3F1"};
}

inline std::string expectedAccountId() {
    return "e2cc7feb-8729-b77d-503f-b6c2652e60e4";
}

inline std::string expectedPublicKeyId() {
    return "42c19fc7-72ff-a646-5f99-e505c9522e19";
}

inline std::vector<unsigned char> expectedPublicKeyData() {
    return virgil::crypto::foundation::VirgilBase64::decode(
        "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHYk1CUUdCeXFHU000OUFnRUdDU3NrQXdN"
        "Q0NBRUJEUU9CZ2dBRW1lMWczS2RicHdUY0UvSE4yc2JyOVZUYwo0ai9rSGtxVTg0Ry84Q2Zk"
        "YkYzblRJRENsQ0l0bk1NeTQxanUxY0VVV0N6eFVWNEFobmFMeUFzY0V6b0s2UXhKClpVQkky"
        "YTVrRmc5aDJUcW9TOStIQkhxTG5wYmhEdk03b1ZOaFJJdngvL2gvSXFzVUNjNTd6NnVMVjlC"
        "T05aTEwKSVRENWN1K3VKSzlzZVJoZWtrRT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
    );
}

inline std::vector<unsigned char> expectedPrivateKeyData() {
    return virgil::crypto::foundation::VirgilBase64::decode(
        "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1JSGFBZ0VCQkVCTy80ZDU2Rkc5WjZC"
        "UkdMdnYzL2U2T2hjSUhBM1d4aWZOVUlQYzZCSjhOQzZYZGs2ckEzeW8KQllFYlQzVlhGc1dwW"
        "Ew2VTg2aE1sTkFObG4zMXp5RUlvQXNHQ1Nza0F3TUNDQUVCRGFHQmhRT0JnZ0FFbWUxZwozS2"
        "RicHdUY0UvSE4yc2JyOVZUYzRqL2tIa3FVODRHLzhDZmRiRjNuVElEQ2xDSXRuTU15NDFqdTF"
        "jRVVXQ3p4ClVWNEFobmFMeUFzY0V6b0s2UXhKWlVCSTJhNWtGZzloMlRxb1M5K0hCSHFMbnBi"
        "aER2TTdvVk5oUkl2eC8vaC8KSXFzVUNjNTd6NnVMVjlCT05aTExJVEQ1Y3UrdUpLOXNlUmhla"
        "2tFPQotLS0tLUVORCBFQyBQUklWQVRFIEtFWS0tLS0tCg=="
    );
}

inline virgil::sdk::keys::client::Credentials expectedCredentialsPubIdKey() {
    return virgil::sdk::keys::client::Credentials(expectedPublicKeyId(), expectedPrivateKeyData());
}

inline virgil::sdk::keys::model::UserData expectedUserData1() {
    virgil::sdk::keys::model::UserData userData =
            virgil::sdk::keys::model::UserData::email("user@virgilsecurity.com");
    userData.accountId(expectedAccountId());
    userData.publicKeyId(expectedPublicKeyId());
    userData.userDataId("eae1d29d-a81a-9d19-ba43-33d0ce320f54");
    userData.isConfirmed(false);
    return userData;
}

inline virgil::sdk::keys::model::UserData expectedUserData2() {
    virgil::sdk::keys::model::UserData userData =
            virgil::sdk::keys::model::UserData::email("user@gmail.com");
    userData.accountId(expectedAccountId());
    userData.publicKeyId(expectedPublicKeyId());
    userData.userDataId("5be1a153-0787-3456-5faf-42c446c1140f");
    userData.isConfirmed(false);
    return userData;
}

inline virgil::sdk::keys::model::UserData expectedUserData3() {
    virgil::sdk::keys::model::UserData userData =
            virgil::sdk::keys::model::UserData::firstName("Mark");
    userData.accountId(expectedAccountId());
    userData.publicKeyId(expectedPublicKeyId());
    userData.userDataId("3433be27-eb46-f935-57d6-4a5703da35ee");
    userData.isConfirmed(false);
    return userData;
}

inline virgil::sdk::keys::model::UserData expectedUserData4() {
    virgil::sdk::keys::model::UserData userData =
            virgil::sdk::keys::model::UserData::lastName("Smith");
    userData.accountId(expectedAccountId());
    userData.publicKeyId(expectedPublicKeyId());
    userData.userDataId("3d7b8881-9273-58ec-8dcc-01737ecacb97");
    userData.isConfirmed(false);
    return userData;
}

inline virgil::sdk::keys::model::PublicKey expectedPublicKey() {
    virgil::sdk::keys::model::PublicKey publicKey;
    publicKey.accountId(expectedAccountId());
    publicKey.publicKeyId(expectedPublicKeyId());
    publicKey.key(expectedPublicKeyData());
    return publicKey;
}

inline virgil::sdk::keys::model::PublicKey expectedPublicKeyWithUserData() {
    virgil::sdk::keys::model::PublicKey publicKey = expectedPublicKey();
    publicKey.userData().push_back(expectedUserData1());
    publicKey.userData().push_back(expectedUserData2());
    publicKey.userData().push_back(expectedUserData3());
    publicKey.userData().push_back(expectedUserData4());
    return publicKey;
}

inline std::string publicKeyAddRequestBody() {
    return (R"(
        {
            "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHYk1CUUdCeXFHU000OUFnRUdDU3NrQXdN Q0NBRUJEUU9CZ2dBRVorVEt6SDMxSXRFNFZmMU8vczZHNVQ2NAovRjYwTk80WDhlcUlvM1lNQ UhKOE1LbHMybFE4QTloY1VLbzFJdkxiYm5BMTVhUzNITmVMWHVtckM0aDEvQXdZCnBkQ0h4Y3 EvQ29rYWNNWlRld2pVcnNmdUhxREp2REtYY0d3aWZMWGdVenNmT1FaRTJlNkJhOFcySXZicHc 0Z0cKaHpjaWFRZkJJd0IvSkdtMEwxZz0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
            "user_data" : [
                {
                    "class": "user_id",
                    "type": "email",
                    "value": "user@virgilsecurity.com"
                },
                {
                    "class": "user_id",
                    "type": "email",
                    "value": "user@gmail.com"
                },
                {
                    "class": "user_info",
                    "type": "first_name",
                    "value": "Mark"
                },
                {
                    "class": "user_info",
                    "type": "last_name",
                    "value": "Smith"
                }
            ],
            "request_sign_uuid": "57e0a766-28ef-355e-7ca2-d8a2dcf23fc4"
        }
    )"_json).dump();
}

#endif /* HELPERS_H */
