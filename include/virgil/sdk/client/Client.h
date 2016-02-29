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

#ifndef VIRGIL_SDK_CLIENT_H
#define VIRGIL_SDK_CLIENT_H

#include <string>
#include <functional>
#include <memory>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/Credentials.h>
#include <virgil/sdk/models/Card.h>
#include <virgil/sdk/http/Response.h>

namespace virgil {
namespace sdk {
    namespace client {
        /**
         * @brief This class encapsulates common state and error check for all clients
         */
        class Client {
        public:
            /**
             * @brief Callback function to perform load of the Virgil Service Card
             */
            typedef std::function<virgil::sdk::models::Card()> CardProviderFunc;

        public:
            /**
             * @brief Create client and configures it with correspond Virgil Card
             *
             * @param accessToken - provides an authenticated secure access token to the Virgil Keys Service
             *                      and is passed with each API call
             * @param baseServiceUri - base service URI
             * @param cardProviderFunc - callback function to perform load of the Virgil Service Card
             *
             * @note First you must create a free Virgil Security developer’s account by signing up.
             *       Once you have your account you can sign in and generate an access token for your application.
            */
            Client(const std::string& accessToken, const std::string& baseServiceUri,
                   CardProviderFunc cardProviderFunc);

            /**
             * @brief Return access token
             *
             * Return authenticated secure access token to the Virgil Keys Service.
             * It MUST be passed to each API call.
             */
            virtual std::string getAccessToken() const;
            /**
             * @brief Return base service uri token
             * @note Base service URI does not contain trailing slash.
             */
            virtual std::string getBaseServiceUri() const;
            /**
             * @brief Perform lasy load for underlying Virgil Service Card and return it
             *
             * @return Virgil Card that is registered on the Virgil Keys Service for underlying service
             * @throw std::runtime_error, if lasy load fails
             */
            virtual virgil::sdk::models::Card getServiceCard() const;

        protected:
            /**
             * @brief Perform crypto verification of the given response
             *
             * @param response - response to be verified
             *
             * @throw std::runtime_exception if given response verification failed
             */
            virtual void verifyResponse(const virgil::sdk::http::Response& response) const;

        private:
            std::string accessToken_;
            std::string baseServiceUri_;
            CardProviderFunc cardProviderFunc_;
            mutable std::shared_ptr<virgil::sdk::models::Card> serviceCard_;
        };
    }
}
}

#endif /* VIRGIL_SDK_CLIENT_H */
