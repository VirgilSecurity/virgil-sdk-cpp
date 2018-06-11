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

#ifndef VIRGIL_SDK_JWTGENERATOR_H
#define VIRGIL_SDK_JWTGENERATOR_H

#include <memory>
#include <virgil/sdk/crypto/Crypto.h>
#include <virgil/sdk/jwt/Jwt.h>
#include <unordered_map>

namespace virgil {
    namespace sdk {
        namespace jwt {
            class JwtGenerator {
            public:
                JwtGenerator(crypto::keys::PrivateKey apiKey,
                             std::string apiPublicKeyIdentifier,
                             std::shared_ptr<crypto::Crypto> crypto,
                             std::string appId,
                             int ttl);

                Jwt generateToken(const std::string& identity,
                                  const std::unordered_map<std::string, std::string>& additionalData
                                  = std::unordered_map<std::string, std::string>()) const;

                const crypto::keys::PrivateKey& apiKey() const;

                const std::string& apiPublicKeyIdentifier() const;

                const std::shared_ptr<crypto::Crypto>& crypto() const;

                const std::string& appId() const;

                int ttl() const;

            private:
                crypto::keys::PrivateKey apiKey_;
                std::string apiPublicKeyIdentifier_;
                std::shared_ptr<crypto::Crypto> crypto_;
                std::string appId_;
                int ttl_;
            };
        }
    }
}

#endif //VIRGIL_SDK_JWTGENERATOR_H