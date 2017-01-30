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

#include <virgil/sdk/client/models/SearchCardsCriteria.h>

using virgil::sdk::client::models::SearchCardsCriteria;
using virgil::sdk::client::models::CardScope;

SearchCardsCriteria SearchCardsCriteria::createCriteria(const std::vector<std::string>& identities,
                                                        CardScope scope, const std::string& identityType) {
    return SearchCardsCriteria(identities, identityType, std::make_unique<CardScope>(scope));
}

SearchCardsCriteria SearchCardsCriteria::createCriteria(const std::vector<std::string>& identities,
                                                        const std::string& identityType) {
    return SearchCardsCriteria(identities, identityType, nullptr);
}

SearchCardsCriteria SearchCardsCriteria::createCriteria(const std::vector<std::string>& identities,
                                                        CardScope scope) {
    return SearchCardsCriteria(identities, "", std::make_unique<CardScope>(scope));
}

SearchCardsCriteria SearchCardsCriteria::createCriteria(const std::vector<std::string>& identities) {
    return SearchCardsCriteria(identities, "", nullptr);
}

SearchCardsCriteria::SearchCardsCriteria(const SearchCardsCriteria &other)
        : identities_(other.identities()), identityType_(other.identityType()) {
    if (other.scope() != nullptr) {
        scope_ = std::make_unique<CardScope>(*other.scope());
    }
}

SearchCardsCriteria& SearchCardsCriteria::operator=(const SearchCardsCriteria &other) {
    identities_ = other.identities();
    identityType_ = other.identityType();

    if (other.scope() != nullptr) {
        scope_ = std::make_unique<CardScope>(*other.scope());
    }

    return *this;
}

SearchCardsCriteria::SearchCardsCriteria(std::vector<std::string> identities, std::string identityType,
                                         std::unique_ptr<CardScope> scope)
        : identities_(std::move(identities)), identityType_(std::move(identityType)), scope_(std::move(scope)) {
}
