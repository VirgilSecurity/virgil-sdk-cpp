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

#include <virgil/sdk/privatekeys/client/ContainerEndpoint.h>
#include <virgil/sdk/privatekeys/client/AuthEndpoint.h>
#include <virgil/sdk/privatekeys/client/PrivateKeysClient.h>
#include <virgil/sdk/privatekeys/client/PrivateKeyEndpoint.h>

using virgil::sdk::privatekeys::client::AuthEndpointBase;
using virgil::sdk::privatekeys::client::AuthEndpoint;
using virgil::sdk::privatekeys::client::PrivateKeysClient;
using virgil::sdk::privatekeys::client::ContainerEndpointBase;
using virgil::sdk::privatekeys::client::ContainerEndpoint;
using virgil::sdk::privatekeys::client::KeysClientConnection;
using virgil::sdk::privatekeys::client::PrivateKeyEndpointBase;
using virgil::sdk::privatekeys::client::PrivateKeyEndpoint;


const std::string PrivateKeysClient::kBaseAddressDefault = "https://keys-private.virgilsecurity.com";


namespace virgil { namespace sdk { namespace privatekeys { namespace client {
    class KeysClientImpl {
    public:
        explicit KeysClientImpl(const std::shared_ptr<KeysClientConnection>& connection)
                : authEndpoint(connection), privateKeyEndpoint(connection), containerEndpoint(connection) {}
    public:
        AuthEndpoint authEndpoint;
        PrivateKeyEndpoint privateKeyEndpoint;
        ContainerEndpoint containerEndpoint;
    };

}}}}


PrivateKeysClient::PrivateKeysClient(const std::shared_ptr<KeysClientConnection>& connection)
        : impl_(std::make_shared<KeysClientImpl>(connection)) {
}

PrivateKeysClient::PrivateKeysClient(const std::string& appToken, const std::string& baseAddress)
        : impl_(std::make_shared<KeysClientImpl>(std::make_shared<KeysClientConnection>(appToken, baseAddress))) {
}

AuthEndpointBase& PrivateKeysClient::auth() {
    return impl_->authEndpoint;
}

PrivateKeyEndpointBase& PrivateKeysClient::privateKey() {
    return impl_->privateKeyEndpoint;
}

ContainerEndpointBase& PrivateKeysClient::container() {
    return impl_->containerEndpoint;
}
