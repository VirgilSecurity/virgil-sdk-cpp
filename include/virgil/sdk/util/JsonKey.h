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

namespace virgil {
namespace sdk {
    namespace util {
        /**
         * @brief This class holds string constants of Json keys.
         *
         * @note This class belongs to the **private** API
         */
        class JsonKey {
        public:
            /**
             * @property id
             * @brief Json Key that points object's identifier
             */
            static const std::string id;
            /**
             * @property publicKey
             * @brief Json Key that points Public Key object
             */
            static const std::string publicKey;
            /**
             * @property privateKey
             * @brief Json Key that points Private Key object
             */
            static const std::string privateKey;
            /**
             * @property createdAt
             * @brief Json Key that points timestamp string value
             */
            static const std::string createdAt;
            /**
             * @property cards
             * @brief Json Key that points collection of Virgil Cards objects
             */
            static const std::string cards;
            /**
             * @property cardId
             * @brief Json Key that points Virgil Card's identifier
             */
            static const std::string cardId;
            /**
             * @property authorizedBy
             * @brief Json Key that points boolean property which tells whether entity is confirmed, or not
             */
            static const std::string authorizedBy;
            /**
             * @property hash
             * @brief Json Key that points Virgil Card's hash
             */
            static const std::string hash;
            /**
             * @property identity
             * @brief Json Key that points Virgil Identity object
             */
            static const std::string identity;
            /**
             * @property identities
             * @brief Json Key that points collection of Virgil Identity objects
             */
            static const std::string identities;
            /**
             * @property type
             * @brief Json Key that points enumeration which represents Virgil Identity type
             */
            static const std::string type;
            /**
             * @property value
             * @brief Json Key that points string which represents Virgil Identity value
             */
            static const std::string value;
            /**
             * @property publicKeyId
             * @brief Json Key that points
             */
            static const std::string publicKeyId;
            /**
             * @property data
             * @brief Json Key that points Virgil Card's custom data object
             */
            static const std::string data;
            /**
             * @property includeUnauthorized
             * @brief Json Key that points boolean value which tell to include unconfirmed Virgil Cards, or not
             */
            static const std::string includeUnauthorized;
            /**
             * @property error
             * @brief Json Key that points Error object
             */
            static const std::string error;
            /**
             * @property errorCode
             * @brief Json Key that points points Error code
             */
            static const std::string errorCode;
            /**
             * @property extraFields
             * @brief Json Key that points parameter will be passed back in an email in a
             * hidden form with extra hidden fields
             */
            static const std::string extraFields;
            /**
             * @property confirmationCode
             * @brief Json Key that points identity confirmation code string
             */
            static const std::string confirmationCode;
            /**
             * @property actionId
             * @brief Json Key that points action identifier string
             */
            static const std::string actionId;
            /**
             * @property token
             * @brief Json Key that points token
             */
            static const std::string token;
            /**
             * @property timeToLive
             * @brief Json Key that points validation token time to live in seconds
             */
            static const std::string timeToLive;
            /**
             * @property countToLive
             * @brief Json Key that points validation token count to live in usage count
             */
            static const std::string countToLive;
            /**
             * @property validationToken
             * @brief Json Key that points validation token string
             */
            static const std::string validationToken;
            /**
             * @property responsePassword
             * @brief Json Key that points password which is used to encrypt a response from the Private Keys Service
             */
            static const std::string responsePassword;

        private:
            JsonKey();
        };
    }
}
}

#endif /* VIRGIL_SDK_UTIL_JSON_KEY_H */
