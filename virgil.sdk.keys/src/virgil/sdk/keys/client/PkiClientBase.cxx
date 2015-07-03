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

#include <virgil/sdk/keys/client/PkiClientBase.h>
using virgil::sdk::keys::client::PkiClientBase;

#include <virgil/sdk/keys/client/PublicKeyClient.h>
using virgil::sdk::keys::client::PublicKeyClient;
#include <virgil/sdk/keys/client/PublicKeyClientBase.h>
using virgil::sdk::keys::client::PublicKeyClientBase;

#include <virgil/sdk/keys/client/UserDataClient.h>
using virgil::sdk::keys::client::UserDataClient;
#include <virgil/sdk/keys/client/UserDataClientBase.h>
using virgil::sdk::keys::client::UserDataClientBase;

namespace virgil { namespace sdk { namespace keys { namespace client {
    class PkiClientBaseImpl {
    public:
        explicit PkiClientBaseImpl(const std::shared_ptr<http::Connection>& connection) :
                publicKeyClient(connection), userDataClient(connection) {
        }
    public:
        PublicKeyClientBase publicKeyClient;
        UserDataClientBase userDataClient;
    };
}}}}

PkiClientBase::PkiClientBase(const std::shared_ptr<http::Connection>& connection)
        : PkiClient(connection), impl_(std::make_shared<PkiClientBaseImpl>(connection)) {
}

PublicKeyClient& PkiClientBase::publicKey() {
    return impl_->publicKeyClient;
}

UserDataClient& PkiClientBase::userData() {
    return impl_->userDataClient;
}
