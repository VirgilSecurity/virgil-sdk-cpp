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

#include <virgil/sdk/client/models/ClientCommon.h>

using virgil::sdk::client::models::CardScope;
using virgil::sdk::client::models::CardRevocationReason;

std::string virgil::sdk::client::models::cardScopeToStr(CardScope scope) {
    switch (scope) {
        case CardScope::application: return "application";
        case CardScope::global: return "global";
    }
}

CardScope virgil::sdk::client::models::strToCardScope(const std::string &scopeStr) {
    if (scopeStr == "application") {
        return CardScope::application;
    }
    else if (scopeStr == "global") {
        return CardScope::global;
    }
    else {
        return CardScope::application;
    }
}

std::string virgil::sdk::client::models::cardRevocationReasonToStr(CardRevocationReason reason) {
    switch (reason) {
        case CardRevocationReason::unspecified: return "unspecified";
        case CardRevocationReason::compromised: return "compromised";
    }
}

CardRevocationReason virgil::sdk::client::models::strToCardRevocationReason(const std::string &reasonStr) {
    if (reasonStr == "unspecified") {
        return CardRevocationReason::unspecified;
    }
    else if (reasonStr == "compromised") {
        return CardRevocationReason::compromised;
    }
    else {
        return CardRevocationReason::unspecified;
    }
}
