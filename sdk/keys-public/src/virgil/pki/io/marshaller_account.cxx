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

#include <virgil/pki/model/Account.h>
using virgil::pki::model::Account;

#include <virgil/pki/model/PublicKey.h>
using virgil::pki::model::PublicKey;

namespace virgil { namespace pki { namespace io {
    /**
     * @brief marshaller<Account> specialization.
     */
    template <>
    class marshaller<Account> {
    public:
        template <int INDENT = -1>
        static std::string toJson(const Account& account, bool deep = false) {
            json accountJson = json::object();
            accountJson[JsonKey::id] = {
                {JsonKey::accountId, account.accountId()}
            };

            json publicKeysJson = json::array();
            if (deep) {
                for (auto publicKey : account.publicKeys()) {
                    publicKeysJson.push_back(json::parse(marshaller<PublicKey>::toJson(publicKey, deep)));
                }
            }
            if (publicKeysJson.size() > 0) {
                accountJson[JsonKey::publicKeys] = publicKeysJson;
            }

            return accountJson.dump(INDENT);
        }
        static Account fromJson(const std::string& jsonString) {
            Account account;
            json accountJson = json::parse(jsonString);
            account.accountId(accountJson[JsonKey::id][JsonKey::accountId]);

            json publicKeysJson = accountJson[JsonKey::publicKeys];
            if (publicKeysJson.is_array()) {
                for (auto publicKeyJson : publicKeysJson) {
                    account.publicKeys().push_back(marshaller<PublicKey>::fromJson(publicKeyJson.dump()));
                }
            }
            return account;
        }
    private:
        marshaller() {};
    };
}}}

void marshaller_account_init() {
    virgil::pki::io::marshaller<Account>::toJson<>(Account());
    virgil::pki::io::marshaller<Account>::toJson<2>(Account());
    virgil::pki::io::marshaller<Account>::toJson<4>(Account());
    virgil::pki::io::marshaller<Account>::fromJson("");
}
