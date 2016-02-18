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

#ifndef VIRGIL_SDK_CARDS_CLIENT_H
#define VIRGIL_SDK_CARDS_CLIENT_H

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/Credentials.h>
#include <virgil/sdk/model/Card.h>
#include <virgil/sdk/model/ValidatedIdentity.h>
#include <virgil/sdk/model/CardSign.h>
#include <virgil/sdk/client/Client.h>

#include <virgil/sdk/http/Response.h>
#include <virgil/sdk/http/Request.h>

namespace virgil {
namespace sdk {
    namespace client {
        /**
         * @brief
         */
        class CardsClient : public Client {
        public:
            using Client::Client;

            CardsClient(const std::string& accessToken, const std::string& baseServiceUri);

            virgil::sdk::model::Card create(const virgil::sdk::model::ValidatedIdentity& validatedIdentity,
                                            const virgil::crypto::VirgilByteArray& publicKey,
                                            const virgil::sdk::Credentials& credentials);

            virgil::sdk::model::CardSign trust(const std::string& trustedCardId, const std::string& trustedCardHash,
                                               const std::string& ownerCardId, const Credentials& credentials);

            void untrust(const std::string& trustedCardId, const std::string& ownerCardId,
                         const virgil::sdk::Credentials& credentials);

            std::vector<virgil::sdk::model::Card>
            search(const virgil::sdk::model::Identity& identity,
                   const std::vector<std::string>& relations = std::vector<std::string>(),
                   const bool includeUnconfirmed = true);

            std::vector<virgil::sdk::model::Card> searchApp(const std::string& applicationIdentity);

            std::vector<virgil::sdk::model::Card> getServiceCard(const std::string& serviceIdentity) const;

            void revoke(const std::string& ownerCardId, const virgil::sdk::model::ValidatedIdentity& validatedIdentity,
                        const virgil::sdk::Credentials& credentials);

            std::vector<virgil::sdk::model::Card> get(const std::string& publicKeyId, const std::string& cardId,
                                                      const Credentials& credentials);

            virgil::sdk::model::Card get(const std::string& cardId);

        private:
            virgil::sdk::http::Request getAppCard(const std::string& applicationIdentity) const;
        };
    }
}
}

#endif /* VIRGIL_SDK_CARDS_CLIENT_H */
