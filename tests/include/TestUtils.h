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


#ifndef VIRGIL_SDK_TESTUTILS_H
#define VIRGIL_SDK_TESTUTILS_H

#include <virgil/sdk/client/models/requests/CreateCardRequest.h>
#include <virgil/sdk/client/models/requests/RevokeCardRequest.h>
#include <virgil/sdk/client/models/Card.h>
#include <virgil/sdk/crypto/CryptoInterface.h>
#include <virgil/sdk/crypto/Crypto.h>

#include <TestConst.h>

using virgil::sdk::client::models::requests::CreateCardRequest;
using virgil::sdk::client::models::requests::RevokeCardRequest;
using virgil::sdk::client::models::Card;
using virgil::sdk::crypto::CryptoInterface;
using virgil::sdk::crypto::Crypto;
using virgil::sdk::test::TestConst;

namespace virgil {
namespace sdk {
    namespace test {
        class TestUtils {
        public:
            TestUtils(TestConst consts) : consts(std::move(consts)), crypto_(std::make_shared<Crypto>()) {
            }

            CreateCardRequest instantiateCreateCardRequest(
                    const std::unordered_map<std::string, std::string> &data = {},
                    const std::string &device = "",
                    const std::string &deviceName = "") const;

            RevokeCardRequest instantiateRevokeCardRequest(const Card &card) const;

            static bool checkCardEquality(const Card &card, const CreateCardRequest &request);
            static bool checkCardEquality(const Card &card1, const Card &card2);

            static bool checkCreateCardRequestEquality(const CreateCardRequest &request1, const CreateCardRequest &request2);
            static bool checkRevokeCardRequestEquality(const RevokeCardRequest &request1, const RevokeCardRequest &request2);

            const std::shared_ptr<CryptoInterface>& crypto() const { return crypto_; }

        private:
            const std::shared_ptr<CryptoInterface> crypto_;
            TestConst consts;
        };
    }
}
}

#endif //VIRGIL_SDK_TESTUTILS_H
