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

#ifndef VIRGIL_SDK_PUBLIC_CLIENT_BASE_H
#define VIRGIL_SDK_PUBLIC_CLIENT_BASE_H

#include <string>
#include <vector>

#include <virgil/sdk/Credentials.h>
#include <virgil/sdk/model/ValidationToken.h>
#include <virgil/sdk/model/VirgilCard.h>
#include <virgil/sdk/model/PublicKey.h>


namespace virgil { namespace sdk { namespace client {
    /**
     * @brief Endpoint "/public-key" to the Virgil Public Keys Service (API).
     */
    class PublicKeysClientBase {
    public:
        virtual virgil::sdk::model::VirgilCard getServiceVirgilCard() const = 0;

        virtual void setServiceVirgilCard(const virgil::sdk::model::VirgilCard& virgilCard) = 0;


        virtual virgil::sdk::model::PublicKey get(const std::string& publicKeyId) = 0;

        virtual void revoke(const std::string& publicKeyId,
                const std::vector<virgil::sdk::model::ValidationToken> validationTokens,
                const std::string& virgilCardId, const virgil::sdk::Credentials& credentials) = 0;

    };
}}}

#endif /* VIRGIL_SDK_PUBLIC_CLIENT_BASE_H */
