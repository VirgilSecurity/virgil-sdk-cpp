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

#include <virgil/pki/model/UserData.h>
using virgil::pki::model::UserData;

namespace virgil { namespace pki { namespace io {
    /**
     * @brief marshaller<UserData> specialization.
     */
    template <>
    class marshaller<UserData> {
    public:
        template <int INDENT = -1>
        static std::string toJson(const UserData& userData, bool deep = false) {
            json userDataJson = json::object();
            userDataJson[JsonKey::id] = {
                {JsonKey::accountId, userData.accountId()},
                {JsonKey::publicKeyId, userData.publicKeyId()},
                {JsonKey::userDataId, userData.userDataId()}
            };
            userDataJson[JsonKey::className] = userData.className();
            userDataJson[JsonKey::type] = userData.type();
            userDataJson[JsonKey::value] = userData.value();
            userDataJson[JsonKey::isConfirmed] = userData.isConfirmed();

            return userDataJson.dump(INDENT);
        }
        static UserData fromJson(const std::string& jsonString) {
            UserData userData;
            json userDataJson = json::parse(jsonString);
            userData.accountId(userDataJson[JsonKey::id][JsonKey::accountId]);
            userData.publicKeyId(userDataJson[JsonKey::id][JsonKey::publicKeyId]);
            userData.userDataId(userDataJson[JsonKey::id][JsonKey::userDataId]);
            userData.className(userDataJson[JsonKey::className]);
            userData.type(userDataJson[JsonKey::type]);
            userData.value(userDataJson[JsonKey::value]);
            userData.isConfirmed(userDataJson[JsonKey::isConfirmed]);

            return userData;
        }
    private:
        marshaller() {};
    };
}}}

void marshaller_user_data_init() {
    virgil::pki::io::marshaller<UserData>::toJson(UserData());
    virgil::pki::io::marshaller<UserData>::toJson<2>(UserData());
    virgil::pki::io::marshaller<UserData>::toJson<4>(UserData());
    virgil::pki::io::marshaller<UserData>::fromJson("");
}
