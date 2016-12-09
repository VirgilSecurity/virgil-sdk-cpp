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

#ifndef VIRGIL_SDK_REQUESTSIGNERINTERFACE_H
#define VIRGIL_SDK_REQUESTSIGNERINTERFACE_H

#include <virgil/sdk/crypto/keys/PrivateKey.h>
#include <virgil/sdk/client/models/interfaces/SignableInterface.h>

namespace virgil {
namespace sdk {
namespace client {
    namespace interfaces {
        /*!
         * @brief This interface is designed to sign Requests to the Virgil Service.
         */
        class RequestSignerInterface {
        public:
            /*!
             * @brief Adds owner's signature to given request using provided Private Key
             * @param request request to be signed in form of SignableInterface
             * @param privateKey PrivateKey instance used to sign request
             */
            virtual void selfSign(models::interfaces::SignableInterface &request,
                                  const crypto::keys::PrivateKey &privateKey) const = 0;

            /*!
             * @brief Adds Authority signature to given request using provided Private Key and Application ID
             * @param request request to be signed in form of SignableInterface
             * @param appId std::string which represents Authority identifier (for example, AppID)
             * @param privateKey PrivateKey instance used to sign request
              */
            virtual void authoritySign(models::interfaces::SignableInterface &request,
                                       const std::string &appId,
                                       const crypto::keys::PrivateKey &privateKey) const = 0;

            /*!
             * @brief Virtual destructor
             */
            virtual ~RequestSignerInterface() = default;
        };
    }
}
}
}

#endif //VIRGIL_SDK_REQUESTSIGNERINTERFACE_H
