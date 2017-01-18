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

#ifndef VIRGIL_SDK_CARDRESPONSE_H
#define VIRGIL_SDK_CARDRESPONSE_H

#include <unordered_map>

#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/models/snapshotmodels/CreateCardSnapshotModel.h>

namespace virgil {
namespace sdk {
namespace client {
namespace models {
    namespace responses {
        /*!
         * @brief This class represents response for card requests from the Virgil Service.
         */
        class CardResponse {
        public:
            /*!
             * @brief Required within std::future
             */
            CardResponse() = default;

            /*!
             * @brief Getter.
             * @return std::unordered_map with signatures
             */
            const std::unordered_map<std::string, VirgilByteArray>& signatures() const { return signatures_; };

            /*!
             * @brief Getter.
             * @return snapshot
             */
            const VirgilByteArray& snapshot() const { return snapshot_; };

            /*!
             * @brief Getter.
             * @return CreateCardSnapshotModel
             */
            const snapshotmodels::CreateCardSnapshotModel& model() const { return model_; };

            /*!
             * @brief Getter.
             * @return std::string with card response identifier
             */
            const std::string& identifier() const { return identifier_; };

            /*!
             * @brief Getter.
             * @return std::string with date of card creation (format is yyyy-MM-dd'T'HH:mm:ssZ)
             */
            const std::string& createdAt() const { return createdAt_; };

            /*!
             * @brief Getter.
             * @return
             */
            const std::string& cardVersion() const { return cardVersion_; };

            // This is private API
            //! @cond Doxygen_Suppress
            CardResponse(
                    std::unordered_map<std::string, VirgilByteArray> signatures,
                    VirgilByteArray snapshot,
                    snapshotmodels::CreateCardSnapshotModel model,
                    std::string identifier,
                    std::string createdAt,
                    std::string cardVersion);
            //! @endcond

        private:
            std::unordered_map<std::string, VirgilByteArray> signatures_;
            VirgilByteArray snapshot_;
            snapshotmodels::CreateCardSnapshotModel model_;
            std::string identifier_;
            std::string createdAt_;
            std::string cardVersion_;
        };
    }
}
}
}
}

#endif //VIRGIL_SDK_CARDRESPONSE_H
