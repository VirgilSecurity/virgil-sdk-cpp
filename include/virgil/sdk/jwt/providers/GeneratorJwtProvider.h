/**
 * Copyright (C) 2018 Virgil Security Inc.
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

#ifndef VIRGIL_SDK_GENERATORJWTPROVIDER_H
#define VIRGIL_SDK_GENERATORJWTPROVIDER_H

#include <virgil/sdk/jwt/interfaces/AccessTokenProviderInterface.h>
#include <virgil/sdk/jwt/JwtGenerator.h>

namespace virgil {
    namespace sdk {
        namespace jwt {
            namespace providers {
                class GeneratorJwtProvider : public interfaces::AccessTokenProviderInterface {
                public:
                    GeneratorJwtProvider(const JwtGenerator& jwtGenerator,
                                         const std::string& defaultIdentity,
                                         const std::unordered_map<std::string, std::string>& additionalData
                                         = std::unordered_map<std::string, std::string>());

                    std::future<std::shared_ptr<interfaces::AccessTokenInterface>> getToken(const TokenContext& tokenContext);

                    const JwtGenerator& jwtGenerator() const;

                    const std::string& defaultIdentity() const;

                    const std::unordered_map<std::string, std::string>& additionalData() const;

                private:
                    JwtGenerator jwtGenerator_;
                    std::string defaultIdentity_;
                    std::unordered_map<std::string, std::string> additionalData_;
                };
            }
        }
    }
}

#endif //VIRGIL_SDK_GENERATORJWTPROVIDER_H
