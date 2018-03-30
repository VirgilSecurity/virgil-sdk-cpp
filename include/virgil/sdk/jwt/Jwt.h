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

#ifndef VIRGIL_SDK_JWT_H
#define VIRGIL_SDK_JWT_H

#include <virgil/sdk/jwt/interfaces/AccessTokenInterface.h>
#include <virgil/sdk/jwt/JwtHeaderContent.h>
#include <virgil/sdk/jwt/JwtBodyContent.h>

namespace virgil {
    namespace sdk {
        namespace jwt {
            class Jwt : public interfaces::AccessTokenInterface {
            public:
                Jwt(const JwtHeaderContent& headerContent,
                    const JwtBodyContent& bodyContent,
                    const VirgilByteArray& signatureContent);

                static Jwt parse(const std::string& stringRepresentation);

                const JwtHeaderContent& headerContent() const;

                const JwtBodyContent& bodyContent() const;

                const VirgilByteArray& signatureContent() const;

                const std::string& stringRepresentation() const;

                const std::string& identity() const;

                const VirgilByteArray& dataToSign() const;

                bool isExpired() const;

                static VirgilByteArray dataToSign(const JwtHeaderContent& headerContent,
                                                  const JwtBodyContent& bodyContent);

            private:
                JwtHeaderContent headerContent_;
                JwtBodyContent bodyContent_;
                VirgilByteArray signatureContent_;
                std::string stringRepresentation_;
                VirgilByteArray dataToSign_;

                const std::string signatureBase64Url() const;
            };
        }
    }
}

#endif //VIRGIL_SDK_JWT_H
