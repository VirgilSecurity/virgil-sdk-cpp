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

#include <virgil/sdk/keys/client/KeysClient.h>

#include <virgil/sdk/keys/client/KeysClientConnection.h>
#include <virgil/sdk/keys/client/PublicKeyClientBase.h>
#include <virgil/sdk/keys/client/PublicKeyClient.h>
#include <virgil/sdk/keys/client/UserDataClientBase.h>
#include <virgil/sdk/keys/client/UserDataClient.h>

using virgil::sdk::keys::client::KeysClient;
using virgil::sdk::keys::client::KeysClientConnection;
using virgil::sdk::keys::client::PublicKeyClientBase;
using virgil::sdk::keys::client::PublicKeyClient;
using virgil::sdk::keys::client::UserDataClientBase;
using virgil::sdk::keys::client::UserDataClient;

const std::string KeysClient::kBaseAddressDefault = "https://keys.virgilsecurity.com/";

namespace virgil { namespace sdk { namespace keys { namespace client {
    class KeysClientImpl {
    public:
        explicit KeysClientImpl(const std::shared_ptr<KeysClientConnection>& connection)
                : publicKeyClient(connection), userDataClient(connection) {
        }
    public:
        PublicKeyClient publicKeyClient;
        UserDataClient userDataClient;
    };
}}}}

KeysClient::KeysClient(const std::shared_ptr<KeysClientConnection>& connection)
        : impl_(std::make_shared<KeysClientImpl>(connection)) {
}

KeysClient::KeysClient(const std::string& appToken, const std::string& baseAddress)
        : impl_(std::make_shared<KeysClientImpl>(std::make_shared<KeysClientConnection>(appToken, baseAddress))) {
}

PublicKeyClientBase& KeysClient::publicKey() {
    return impl_->publicKeyClient;
}

UserDataClientBase& KeysClient::userData() {
    return impl_->userDataClient;
}
