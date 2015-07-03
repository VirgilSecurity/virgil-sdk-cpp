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

#include <virgil/pki/io/marshaller.h>

#include <json.hpp>
using json = nlohmann::json;

#include <virgil/string/JsonKey.h>
using virgil::string::JsonKey;

#include <virgil/string/Base64.h>
using virgil::string::Base64;

#include <virgil/pki/model/PublicKey.h>
using virgil::pki::model::PublicKey;

#include <virgil/pki/model/UserData.h>
using virgil::pki::model::UserData;

namespace virgil { namespace pki { namespace io {
    /**
     * @brief marshaller<PublicKey> specialization.
     */
    template <>
    class marshaller<PublicKey> {
    public:
        template <int INDENT = -1>
        static std::string toJson(const PublicKey& publicKey, bool deep = false) {
            json publicKeyJson = json::object();
            publicKeyJson[JsonKey::id] = {
                {JsonKey::accountId, publicKey.accountId()},
                {JsonKey::publicKeyId, publicKey.publicKeyId()}
            };

            publicKeyJson[JsonKey::publicKey] = Base64::encode(publicKey.key());

            json userDataJson = json::array();
            if (deep) {
                for (auto userData : publicKey.userData()) {
                    userDataJson.push_back(json::parse(marshaller<UserData>::toJson(userData, deep)));
                }
            }
            if (userDataJson.size() > 0) {
                publicKeyJson[JsonKey::userData] = userDataJson;
            }

            return publicKeyJson.dump(INDENT);
        }
        static PublicKey fromJson(const std::string& jsonString) {
            PublicKey publicKey;
            json publicKeyJson = json::parse(jsonString);
            publicKey.accountId(publicKeyJson[JsonKey::id][JsonKey::accountId]);
            publicKey.publicKeyId(publicKeyJson[JsonKey::id][JsonKey::publicKeyId]);
            publicKey.key(Base64::decode(publicKeyJson[JsonKey::publicKey]));

            json userDataJson = publicKeyJson[JsonKey::publicKeys];
            if (userDataJson.is_array()) {
                for (auto specificUserDataJson : userDataJson) {
                    publicKey.userData().push_back(marshaller<UserData>::fromJson(specificUserDataJson.dump()));
                }
            }
            return publicKey;
        }
    private:
        marshaller() {};
    };
}}}

void marshaller_public_key_init() {
    virgil::pki::io::marshaller<PublicKey>::toJson(PublicKey());
    virgil::pki::io::marshaller<PublicKey>::toJson<2>(PublicKey());
    virgil::pki::io::marshaller<PublicKey>::toJson<4>(PublicKey());
    virgil::pki::io::marshaller<PublicKey>::fromJson("");
}
