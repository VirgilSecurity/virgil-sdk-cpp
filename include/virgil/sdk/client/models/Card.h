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


#ifndef VIRGIL_SDK_CARD_H
#define VIRGIL_SDK_CARD_H

#include <unordered_map>
#include <string>
#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/models/ClientCommon.h>

using std::string;
using std::unordered_map;
using virgil::sdk::VirgilByteArray;
using virgil::sdk::client::models::CardScope;

namespace virgil {
namespace sdk {
namespace client {
    namespace models {
        class Card {
        public:
            Card() {}

            Card(string identifier, string identity, string identityType, VirgilByteArray publicKeyData,
                VirgilByteArray data, CardScope scope, unordered_map<string, string> info,
                string createdAt, string cardVersion);

            // getters
            const string& identifier() const { return identifier_; }
            const string& identity() const { return identity_; }
            const string& identityType() const { return identityType_; }
            const VirgilByteArray& publicKeyData() const { return publicKeyData_; }
            const VirgilByteArray& data() const { return data_; }
            CardScope scope() const { return scope_; }
            const unordered_map<string, string>& info() const { return info_; }
            const string& createdAt() const { return createdAt_; }
            const string& cardVersion() const { return cardVersion_; }

        private:
            string identifier_;
            string identity_;
            string identityType_;
            VirgilByteArray publicKeyData_;
            VirgilByteArray data_;
            CardScope scope_;
            unordered_map<string, string> info_;
            string createdAt_;
            string cardVersion_;
        };
    }
}
}
}

#endif //VIRGIL_SDK_CARD_H
