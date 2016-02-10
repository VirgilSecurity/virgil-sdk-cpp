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

#ifndef VIRGIL_SDK_VIRGIL_CARDS_CLIENT_H
#define VIRGIL_SDK_VIRGIL_CARDS_CLIENT_H

#include <virgil/sdk/client/VirgilCardsClientBase.h>
#include <virgil/sdk/http/Response.h>
#include <virgil/sdk/http/Request.h>


namespace virgil { namespace sdk { namespace client {
    /**
     * @brief
     */
    class VirgilCardsClient final : public VirgilCardsClientBase {
    public:
        VirgilCardsClient(const std::string& accessToken, const std::string& baseServiceUri);

        virgil::sdk::model::VirgilCard getServiceVirgilCard() const override;

        void setServiceVirgilCard(const virgil::sdk::model::VirgilCard& publicKeysServiceCard) override;


        virgil::sdk::model::VirgilCard create(const virgil::sdk::model::ValidationToken& validationToken,
                const virgil::crypto::VirgilByteArray& publicKey,
                const virgil::sdk::Credentials& credentials) override;

        virgil::sdk::model::TrustCardResponse trust(const std::string& trustedCardId,
                const std::string& trustedCardHash, const std::string& ownerCardId,
                const Credentials& credentials) override;

        void untrust(const std::string& trustedCardId, const std::string& ownerCardId,
                const virgil::sdk::Credentials& credentials) override;

        std::vector<virgil::sdk::model::VirgilCard> search(
            const virgil::sdk::model::Identity& identity,
            const bool includeUnconfirmed = true,
            const std::vector<std::string>& relations = std::vector<std::string>()
        ) override;

        std::vector<virgil::sdk::model::VirgilCard> searchApp(const std::string& applicationIdentity) override;

        std::vector<virgil::sdk::model::VirgilCard> getServiceCard(const std::string& serviceIdentity) override;

        void revoke(const std::string& ownerCardId,
                const virgil::sdk::model::ValidationToken& validationToken,
                const virgil::sdk::Credentials& credentials) override;


        std::vector<virgil::sdk::model::VirgilCard> get(const std::string& publicKeyId,
                const std::string& virgilCardId, const Credentials& credentials) override;

        virgil::sdk::model::VirgilCard get(const std::string& virgilCardId) override;

    private:
        std::string accessToken_;
        std::string baseServiceUri_;
        virgil::sdk::model::VirgilCard publicKeysServiceCard_;

    private:
        virgil::sdk::http::Request getAppCard(const std::string& applicationIdentity);
        void verifyResponse(const virgil::sdk::http::Response& response);
    };


}}}

#endif /* VIRGIL_SDK_VIRGIL_CARDS_CLIENT_H */
