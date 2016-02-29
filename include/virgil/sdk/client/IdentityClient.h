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

#ifndef VIRGIL_SDK_IDENTITY_CLIENT_H
#define VIRGIL_SDK_IDENTITY_CLIENT_H

#include <virgil/sdk/client/Client.h>

#include <virgil/sdk/dto/ValidatedIdentity.h>
#include <virgil/sdk/dto/Identity.h>
#include <virgil/sdk/http/Request.h>
#include <virgil/sdk/http/Response.h>

namespace virgil {
namespace sdk {
    namespace client {
        /**
         * @brief Entrypoint for interacting with Virgil Identity Service
         *
         * Virgil Identity Service is responsible for validation of user's identities,
         * like email, application, etc. Typical workflow for an email confirmation contains the following steps:
         *   - The process is initiated by invocation of the verify() method
         *   - Identity service generates a confirmation code and sends it to the specified email
         *   - Confirm email by invoke method @link confirm() @endlink with
         *         the confirmation code sent to the email and identity id from the previous step
         *   - Identity service returns the token within class @link virgil::sdk::dto::ValidatedIdentity @endlink,
         *         that can be used to prove that the user is the identity holder
         *   - To verify that the user is identity holder invoke the @link validate() @endlink method
         *         with the token from the previous step
         */
        class IdentityClient : public Client {
        public:
            using Client::Client;
            /**
             * @brief Initiate identity verification process
             * @param identity - user's identity, that is sent to verification
             * @return Unique identifier of the initiated verification action
             */
            std::string verify(const virgil::sdk::dto::Identity& identity);
            /**
             * @brief [brief description]
             * @details [long description]
             *
             * @param actionId - unique identifier that was returned by @link verify() @endlink method
             * @param confirmationCode - unique code, that was sent to the given identity
             * @param timeToLive - limit the lifetime of the token in seconds,
             *                     maximum value is 60 * 60 * 24 * 365 = 1 year,
             *                     default value is 3600 = 1 hour
             * @param countToLive - limit token usage count,
             *                      default value is 1 which means that the token can be used at most one time
             * @return Identity with validation token inside
             */
            virgil::sdk::dto::ValidatedIdentity confirm(const std::string& actionId,
                                                        const std::string& confirmationCode,
                                                        const int timeToLive = 3600, const int countToLive = 1);
            /**
             * @brief Validate given token
             *
             * @param validatedIdentity - identity and token to be validated
             * @return true if given token is valid, false - otherwise
             */
            bool validate(const virgil::sdk::dto::ValidatedIdentity& validatedIdentity);
        };
    }
}
}

#endif /* VIRGIL_SDK_IDENTITY_CLIENT_H */
