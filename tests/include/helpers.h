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

#ifndef HELPERS_H
#define HELPERS_H

#include <string>
#include <vector>

#include <virgil/sdk/models/PublicKeyModel.h>
#include <virgil/sdk/models/PrivateKeyModel.h>
#include <virgil/sdk/dto/ValidatedIdentity.h>
#include <virgil/sdk/models/CardModel.h>
#include <virgil/sdk/util/JsonKey.h>

#include <json.hpp>

namespace virgil {
namespace test {

    nlohmann::json getJsonValidatedIdentity();
    virgil::sdk::dto::ValidatedIdentity getValidatedIdentity();

    nlohmann::json getJsonPublicKey();
    virgil::sdk::models::PublicKeyModel getPublicKey();

    nlohmann::json getJsonCard();
    virgil::sdk::models::CardModel getCard();

    nlohmann::json getJsonResponseCards();
    nlohmann::json getJsonCards();
    std::vector<virgil::sdk::models::CardModel> getCards();

    nlohmann::json getJsonPrivateKey();
    virgil::sdk::models::PrivateKeyModel getPrivateKey();
}
}

#endif /* HELPERS_H */
