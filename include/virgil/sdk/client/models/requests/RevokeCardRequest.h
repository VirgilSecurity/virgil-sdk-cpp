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

#ifndef VIRGIL_SDK_REVOKECARDREQUEST_H
#define VIRGIL_SDK_REVOKECARDREQUEST_H

#include <string>

#include <virgil/sdk/client/models/requests/SignableRequest.h>
#include <virgil/sdk/client/models/snapshotmodels/RevokeCardSnapshotModel.h>

namespace virgil {
namespace sdk {
namespace client {
namespace models {
    namespace requests {
        /*!
         * @brief This class represents request for Card Revocation on the Virgil Service.
         */
        class RevokeCardRequest final :
                public SignableRequest<snapshotmodels::RevokeCardSnapshotModel, RevokeCardRequest> {
        public:
            /*!
             * @brief Creates RevokeCardRequest with given arguments.
             * @param cardId std::string with card ID to revoke
             * @param reason CardRevocationReason
             * @return RevokeCardRequest instance initialized with given values
             */
            static RevokeCardRequest createRequest(const std::string &cardId, CardRevocationReason reason);

            // This is private API
            //! @cond Doxygen_Suppress
            RevokeCardRequest(const VirgilByteArray &snapshot,
                              const std::unordered_map<std::string, VirgilByteArray> &signatures
                              = std::unordered_map<std::string, VirgilByteArray>());
            //! @endcond

        private:
            RevokeCardRequest(const std::string &cardId, CardRevocationReason reason);

            RevokeCardRequest(const snapshotmodels::RevokeCardSnapshotModel &model,
                              const std::unordered_map<std::string, VirgilByteArray> &signatures
                                    = std::unordered_map<std::string, VirgilByteArray>());
        };
    }
}
}
}
}

#endif //VIRGIL_SDK_REVOKECARDREQUEST_H
