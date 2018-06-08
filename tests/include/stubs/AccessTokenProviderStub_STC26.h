/**
 * Copyright (C) 2018 Virgil Security Inc.
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

#ifndef VIRGIL_SDK_ACCESSTOKENPROVIDERSTUB_STC26_H
#define VIRGIL_SDK_ACCESSTOKENPROVIDERSTUB_STC26_H

#include <functional>
#include <virgil/sdk/jwt/interfaces/AccessTokenProviderInterface.h>
#include <TestUtils.h>

namespace virgil {
    namespace sdk {
        namespace test {
            namespace stubs {
                class AccessTokenProviderStub_STC26 : public jwt::interfaces::AccessTokenProviderInterface {
                public:
                    AccessTokenProviderStub_STC26(std::string identity, std::function<void(bool forceCallback)> forceCallback);

                    std::future<std::shared_ptr<jwt::interfaces::AccessTokenInterface>> getToken(const jwt::TokenContext& tokenContext);

                private:
                    std::string identity_;
                    std::function<void(bool forceCallback)> forceCallback_;
                    int counter_;
                    TestUtils utils_;
                };
            }
        }
    }
}

#endif //VIRGIL_SDK_ACCESSTOKENPROVIDERSTUB_STC26_H
