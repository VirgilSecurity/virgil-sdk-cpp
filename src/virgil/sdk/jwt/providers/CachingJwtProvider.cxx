/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#include <virgil/sdk/jwt/providers/CachingJwtProvider.h>

using virgil::sdk::jwt::providers::CachingJwtProvider;
using virgil::sdk::jwt::interfaces::AccessTokenInterface;
using virgil::sdk::jwt::TokenContext;
using virgil::sdk::jwt::Jwt;

CachingJwtProvider::CachingJwtProvider(std::function<std::future<std::string>(const TokenContext &)> renewJwtCallback)
        : renewJwtCallback_(std::move(renewJwtCallback)), jwt_(nullptr) {}

std::future<std::shared_ptr<AccessTokenInterface>> CachingJwtProvider::getToken(const TokenContext &tokenContext) {
    auto future = std::async([=]{
        std::promise<std::shared_ptr<AccessTokenInterface>> p;

        if (jwt_ == nullptr || jwt_->isExpired(std::time(0) + 5)) {
            try {
                auto future = renewJwtCallback_(tokenContext);
                auto jwt = Jwt::parse(future.get());
                jwt_ = std::make_shared<Jwt>(jwt);
            } catch (...) {
                p.set_exception(std::current_exception());

                return p.get_future().get();
            }
        }
        p.set_value(jwt_);

        return p.get_future().get();
    });

    return future;
}

const std::function<std::future<std::string>(const TokenContext&)>& CachingJwtProvider::renewJwtCallback() const {
    return renewJwtCallback_;
}

const std::shared_ptr<Jwt>& CachingJwtProvider::jwt() const {
    return jwt_;
}