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

#ifndef VIRGIL_SDK_CARD_ENDPOINT_URI_H
#define VIRGIL_SDK_CARD_ENDPOINT_URI_H

#include <string>

namespace virgil {
namespace sdk {
    namespace endpoints {
        /**
         * @brief This class provide URIs to the Virgil Card endpoints
         * @note All endpoints start with forward slash symbol "/" and contain version
         */
        class CardEndpointUri {
        public:
            /**
             * @brief Returns the endpoint in charge of a Virgil Card creation
             */
            static std::string create();
            /**
             * @brief Returns the endpoint in charge of a Virgil Card grab
             */
            static std::string get(const std::string& cardId);
            /**
             * @brief Returns the endpoint in charge of the Virgil Card searches by provided parameters
             */
            static std::string search();
            /**
             * @brief Returns the endpoint in charge of the Virgil Cards searches by a defined pattern
             */
            static std::string searchGlobal();
            /**
             * @brief Returns the endpoint in charge of the Virgil Cards searches by an email
             */
            static std::string searchGlobalbyEmail();
            /**
             * @brief Returns the endpoint in charge of the Virgil Card revoke
             * @param cardId - Virgil Card identifier
             */
            static std::string revoke(const std::string& cardId);

        private:
            /**
             * @brief Deny object creation
             */
            CardEndpointUri();
        };
    }
}
}

#endif /* VIRGIL_SDK_CARD_ENDPOINT_URI_H */
