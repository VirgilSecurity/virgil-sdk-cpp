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

#ifndef VIRGIL_SDK_CARDCLIENTINTERFACE_H
#define VIRGIL_SDK_CARDCLIENTINTERFACE_H

#include <string>
#include <future>
#include <vector>
#include <virgil/sdk/client/models/RawSignedModel.h>
#include <virgil/sdk/client/models/GetCardResponse.h>

namespace virgil {
    namespace sdk {
        namespace client {
            /*!
             * @brief Interface representing operations with Virgil Cards service
             */
            class CardClientInterface {
            public:
                /*!
                 * @brief Creates Virgil Card instance on the Virgil Cards Service.
                 * Also makes the Card accessible for search/get queries from other users.
                 * RawSignedModel should contain appropriate signatures
                 * @param model signed RawSignedModel to publish
                 * @param token std::string with AccessTokenInterface implementation
                 * @return std::future with RawSignedModel of published Card
                 */
                virtual std::future<models::RawSignedModel> publishCard(const models::RawSignedModel& model,
                                                                        const std::string& token) const = 0;

                /*!
                 * @brief Returns GetCardResponse with RawSignedModel of card from the Virgil Cards Service with given ID, if exists
                 * @param cardId std::string with unique Virgil Card identifier
                 * @param token std::string with AccessTokenInterface implementation
                 * @return std::future with GetCardResponse if Card found
                 */
                virtual std::future<models::GetCardResponse> getCard(const std::string &cardId,
                                                                     const std::string& token) const = 0;

                /*!
                 * @brief Performs search of Virgil Cards using given identity on the Virgil Cards Service
                 * @param identity identity of cards to search
                 * @param token std::string with AccessTokenInterface implementation
                 * @return std::future with std::vector with RawSignedModels of matched Virgil Cards
                 */
                virtual std::future<std::vector<models::RawSignedModel>> searchCards(const std::string &identity,
                                                                                     const std::string& token) const = 0;

                /*!
                 * @brief Virtual destructor
                 */
                virtual ~CardClientInterface() = default;
            };
        }
    }
}

#endif //VIRGIL_SDK_CARDCLIENTINTERFACE_H