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

#ifndef VIRGIL_SDK_CERTIFICATE_CLIENT_H
#define VIRGIL_SDK_CERTIFICATE_CLIENT_H

#include <string>
#include <map>

#include <virgil/sdk/client/Client.h>
#include <virgil/sdk/http/Request.h>
#include <virgil/sdk/http/Response.h>
#include <virgil/sdk/models/CertificateModel.h>
#include <virgil/sdk/dto/ValidatedIdentity.h>

namespace virgil {
    namespace sdk {
        namespace client {
            /**
             * @brief Entrypoint for interacting with Virgil Certificate Service
             *
             * Virgil Certificate Service is a wrapper for 1609
             */
            class CertificateClient : public Client {
            public:
                using Client::Client;
                
                /**
                 * @brief Create validated Virgil Certificate entity
                 *
                 * @param validatedIdentity - identity that was validated by user thru Virgil Identity Service
                 * @param publicKey - Public Key that was generated locally
                 * @param credentials - Private Key + Private Key password
                 * @param customData - the custom data
                 * @return Created Virgil Certificate
                 */
                virgil::sdk::models::CertificateModel
                create(const virgil::sdk::dto::ValidatedIdentity& validatedIdentity,
                       const virgil::crypto::VirgilByteArray& publicKey,
                       const virgil::sdk::Credentials& credentials,
                       const std::map<std::string, std::string>& customData = std::map<std::string, std::string>());
                /**
                 * @brief Revoke validated the Virgil Certificate and all associated data
                 *
                 * @param certificateId - Virgil Certificate Identifier
                 * @param validatedIdentity - entity that is validated via Virgil Identity Service,
                 *                            and associted with given cardId
                 * @param credentials - Private Key that associted with given Certificate
                 */
                void revoke(const std::string & certificateId,
                            const virgil::sdk::dto::ValidatedIdentity& validatedIdentity,
                            const virgil::sdk::Credentials& credentials);
                /**
                 * @brief Performs the pull of a private application's Virgil Certificate
                 *
                 * @param identity - identity to be searched
                 * @return Found Virgil Certificate
                 */
                virgil::sdk::models::CertificateModel pull(const virgil::sdk::dto::Identity & identity);
                
                /**
                 * @brief Performs the pull of the Virgil Root Certificate
                 * @return Virgil Root Certificate
                 */
                virgil::sdk::models::CertificateModel pullRootCertificate();
            
                /**
                 * @brief Performs the pull of the Virgil Certificate Revocation List
                 * @return Virgil Certificate Revocation List
                 */
                void getCRL();
            };
        }
    }
}

#endif /* VIRGIL_SDK_CERTIFICATE_CLIENT_H */
