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

#ifndef VIRGIL_STRING_JSON_KEY_H
#define VIRGIL_STRING_JSON_KEY_H

#include <string>

namespace virgil { namespace sdk { namespace privatekeys { namespace util {
    /**
     * @brief This class holds string constants of Json keys.
     */
    class JsonKey {
    public:
        static const std::string newContainerPassword; /*!< Json key for represents new container password. */
        static const std::string containerPassword; /*!< Json key for container password object. */
        static const std::string authToken; /*!< Json key for authentication token object. */
        static const std::string userData; /*!< Json key for user data object. */
        static const std::string className; /*!< Json key for user data class name. */
        static const std::string type; /*!< Json key for user data type. */
        static const std::string value; /*!< Json key for user data value. */
        static const std::string error; /*!< Json key for error object. */
        static const std::string errorCode; /*!< Json key for error code. */
        static const std::string containerType; /*!< container type. */
        static const std::string requestSignUuid; /*!< request sign uuid. */
        static const std::string confirmToken; /*!< the confirmation token. */
        static const std::string publicKeyId; /*!< Json key for the user public key id. */
        static const std::string privateKey; /*!< Json key for the user private key. */
    private:
        JsonKey();
    };
}}}}

#endif /* VIRGIL_STRING_JSON_KEY_H */
