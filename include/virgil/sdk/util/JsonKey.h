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

#ifndef VIRGIL_SDK_UTIL_JSON_KEY_H
#define VIRGIL_SDK_UTIL_JSON_KEY_H

#include <string>

namespace virgil { namespace sdk { namespace util {
    /**
     * @brief This class holds string constants of Json keys.
     */
    class JsonKey {
    public:
        static const std::string id;
        static const std::string publicKey;
        static const std::string privateKey;
        static const std::string createdAt;
        static const std::string virgilCards;
        static const std::string virgilCardId;
        static const std::string isConfirmed;
        static const std::string hash;
        static const std::string identity;
        static const std::string type;
        static const std::string value;
        static const std::string publicKeyId;
        static const std::string data;
        static const std::string signs;
        static const std::string signerVirgilCardId;
        static const std::string signedVirgilCardId;
        static const std::string signedDigest;
        static const std::string relations;
        static const std::string includeUnconfirmed;
        static const std::string error;
        static const std::string errorCode;
        static const std::string confirmationCode;
        static const std::string actionId;
        static const std::string token;
        static const std::string timeToLive;
        static const std::string countToLive;
        static const std::string validationToken;
        static const std::string responsePassword;

    private:
        JsonKey();
    };
}}}

#endif /* VIRGIL_SDK_UTIL_JSON_KEY_H */
