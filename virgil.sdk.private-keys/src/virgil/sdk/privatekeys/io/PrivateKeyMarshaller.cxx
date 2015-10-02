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

#include <string>

#include <virgil/sdk/privatekeys/io/Marshaller.h>

#include <virgil/sdk/privatekeys/util/JsonKey.h>
#include <virgil/sdk/privatekeys/model/PrivateKey.h>

#include <virgil/crypto/foundation/VirgilBase64.h>

#include <json.hpp>

using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::privatekeys::util::JsonKey;
using virgil::sdk::privatekeys::model::PrivateKey;

using json = nlohmann::json;


namespace virgil { namespace sdk { namespace privatekeys { namespace io {
    /**
     * @brief Marshaller<PrivateKey> specialization.
     */
    template <>
    class Marshaller<PrivateKey> {
    public:
        template <int INDENT = -1>
        static std::string toJson(const PrivateKey& privateKey) {
            json privateKeyJson = json::object();
            privateKeyJson[JsonKey::publicKeyId] = privateKey.publicKeyId();

            std::string encodePrivateKey = VirgilBase64::encode(privateKey.key());
            privateKeyJson[JsonKey::privateKey] = encodePrivateKey;
            return privateKeyJson.dump(INDENT);
        }
        static PrivateKey fromJson(const std::string& jsonString) {
            json typeJson = json::parse(jsonString);
            std::string publicKeyId = typeJson[JsonKey::publicKeyId];
            std::string key = typeJson[JsonKey::privateKey];

            PrivateKey privateKey;
            privateKey.publicKeyId(publicKeyId).key(VirgilBase64::decode(key));
            return privateKey;
        }
    private:
        Marshaller() {};
    };
}}}}

void marshaller_user_data_init() {
    virgil::sdk::privatekeys::io::Marshaller<PrivateKey>::toJson(PrivateKey());
    virgil::sdk::privatekeys::io::Marshaller<PrivateKey>::toJson<2>(PrivateKey());
    virgil::sdk::privatekeys::io::Marshaller<PrivateKey>::toJson<4>(PrivateKey());
    virgil::sdk::privatekeys::io::Marshaller<PrivateKey>::fromJson("");
}
