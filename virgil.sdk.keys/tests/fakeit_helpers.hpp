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

#ifndef FAKEIT_UTILS_HPP
#define FAKEIT_UTILS_HPP

#include <algorithm>
#include <vector>

#include <virgil/sdk/keys/model/PublicKey.h>
#include <virgil/sdk/keys/model/UserData.h>

#include "fakeit.hpp"

template<typename T>
inline auto make_moc_shared(fakeit::Mock<T>& mock)
        -> std::shared_ptr<typename std::remove_reference<decltype(mock.get())>::type> {
    return std::shared_ptr<typename std::remove_reference<decltype(mock.get())>::type>(&mock.get(), [](void *){});
}

inline void checkUserData(const virgil::sdk::keys::model::UserData& lhs,
        const virgil::sdk::keys::model::UserData& rhs) {
    REQUIRE(lhs.accountId() == rhs.accountId());
    REQUIRE(lhs.publicKeyId() == rhs.publicKeyId());
    REQUIRE(lhs.userDataId() == rhs.userDataId());
    REQUIRE(lhs.className() == rhs.className());
    REQUIRE(lhs.type() == rhs.type());
    REQUIRE(lhs.value() == rhs.value());
    REQUIRE(lhs.isConfirmed() == rhs.isConfirmed());
}

inline void checkPublicKeys(const virgil::sdk::keys::model::PublicKey& lhs,
        const virgil::sdk::keys::model::PublicKey& rhs) {
    REQUIRE(lhs.accountId() == rhs.accountId());
    REQUIRE(lhs.publicKeyId() == rhs.publicKeyId());
    REQUIRE(lhs.key() == rhs.key());

    auto userDataComp = [](const virgil::sdk::keys::model::UserData& lhs,
            const virgil::sdk::keys::model::UserData& rhs) -> bool {
        auto valueLhs = lhs.value();
        auto valueRhs = rhs.value();
        return std::lexicographical_compare(valueLhs.begin(), valueLhs.end(), valueRhs.begin(), valueRhs.end());
    };

    std::vector<virgil::sdk::keys::model::UserData> sortedUserDataLhs = lhs.userData();
    std::vector<virgil::sdk::keys::model::UserData> sortedUserDataRhs = rhs.userData();
    std::sort(sortedUserDataLhs.begin(), sortedUserDataLhs.begin(), userDataComp);
    std::sort(sortedUserDataRhs.begin(), sortedUserDataRhs.begin(), userDataComp);

    REQUIRE(sortedUserDataLhs.size() == sortedUserDataRhs.size());
    for (size_t pos = 0; pos < sortedUserDataLhs.size(); ++pos) {
        checkUserData(sortedUserDataLhs[pos], sortedUserDataRhs[pos]);
    }
}

#endif /* FAKEIT_UTILS_HPP */
