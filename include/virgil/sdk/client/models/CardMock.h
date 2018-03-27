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


#ifndef VIRGIL_SDK_CARDMOCK_H
#define VIRGIL_SDK_CARDMOCK_H

#include <unordered_map>
#include <string>

#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/models/ClientCommon.h>
#include <virgil/sdk/client/models/responses/CardResponse.h>
#include <virgil/sdk/client/models/interfaces/Exportable.h>
#include <virgil/sdk/client/models/interfaces/Importable.h>

namespace virgil {
namespace sdk {
namespace client {
    namespace models {
        /*!
         * @brief Model that represents identities on the Virgil Cards Service.
         *
         * Each card has assigned identity of identityType, publicKey (and owner has corresponding private key),
         * info about device on which Card was created, custom payload, version,
         * creation date and scope (global or application)
         */
        class CardMock: interfaces::Exportable, interfaces::Importable<CardMock> {
        public:
            /*!
             * @brief Required within std::future
             */
            CardMock() = default;

            /*!
             * @brief Creates Card instance from CardResponse with response form Virgil Service.
             * @param cardResponse CardResponse instance
             * @return instantiated Card instance
             */
            static CardMock buildCard(const responses::CardResponse &cardResponse);

            std::string exportAsString() const override;

            /// WARNING: Calling side is responsible for validating cardResponse using CardValidator after this import!
            static CardMock importFromString(const std::string &data);

            /*!
             * @brief Getter.
             * @return std::string with card ID
             */
            const std::string& identifier() const { return identifier_; }

            /*!
             * @brief Getter.
             * @return std::string with card identity
             */
            const std::string& identity() const { return identity_; }

            /*!
             * @brief Getter.
             * @return std::string with card identity type
             */
            const std::string& identityType() const { return identityType_; }

            /*!
             * @brief Getter.
             * @return raw representation of Public Key which corresponds to this Card
             */
            const VirgilByteArray& publicKeyData() const { return publicKeyData_; }

            /*!
             * @brief Getter.
             * @return std::unordered_map with custom user payload
             */
            const std::unordered_map<std::string, std::string>& data() const { return data_; }

            /*!
             * @brief Getter.
             * @return CardScope (application or global)
             */
            CardScope scope() const { return scope_; }

            /*!
             * @brief Getter.
             * @return std::unordered_map with info about device on which card was created
             */
            const std::unordered_map<std::string, std::string>& info() const { return info_; }

            /*!
             * @brief Getter.
             * @return std::string with date of Card creation (format is yyyy-MM-dd'T'HH:mm:ssZ)
             */
            const std::string& createdAt() const { return createdAt_; }

            /*!
             * @brief Getter.
             * @return std::string with card version
             */
            const std::string& cardVersion() const { return cardVersion_; }

            /*!
             * @brief Getter.
             * @return Card Response with response from Virgil Service
             */
            const responses::CardResponse& cardResponse() const { return cardResponse_; };

        private:
            CardMock(responses::CardResponse cardResponse, std::string identifier, std::string identity,
                 std::string identityType, VirgilByteArray publicKeyData,
                 std::unordered_map<std::string, std::string> data, CardScope scope,
                 std::unordered_map<std::string, std::string> info, std::string createdAt, std::string cardVersion);

            responses::CardResponse cardResponse_;
            std::string identifier_;
            std::string identity_;
            std::string identityType_;
            VirgilByteArray publicKeyData_;
            std::unordered_map<std::string, std::string> data_;
            CardScope scope_;
            std::unordered_map<std::string, std::string> info_;
            std::string createdAt_;
            std::string cardVersion_;
        };
    }
}
}
}

#endif //VIRGIL_SDK_CARDMOCK_H
