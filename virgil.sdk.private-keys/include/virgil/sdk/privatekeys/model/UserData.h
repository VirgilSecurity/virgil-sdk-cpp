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

#ifndef VIRGIL_SDK_PRIVATE_KEYS_MODEL_USER_DATA_H
#define VIRGIL_SDK_PRIVATE_KEYS_MODEL_USER_DATA_H

#include <memory>
#include <string>


namespace virgil { namespace sdk { namespace privatekeys { namespace model {
    /**
     * @brief Forward declaration.
     */
    //@{
    class PublicKey;
    //@}

    /**
     * @brief Data object represent "Virgil User Data" entity.
     */
    class UserData {
    public:
        /**
         * @name Common object creation
         * @brief Return UserData object with preset fields:
         *     @link className @endlink and @link type @endlink
         */
        //@{
        /**
         * @return UserData object that represents email.
         */
        static UserData email(const std::string& value);
        /**
         * @return UserData object that represents phone.
         */
        static UserData phone(const std::string& value);
        /**
         * @return UserData object that represents application.
         */
        static UserData application(const std::string& value);
        /**
         * @return UserData object that represents domain.
         */
        static UserData domain(const std::string& value);
        /**
         * @return UserData object that represents user's first name.
         */
        static UserData firstName(const std::string& value);
        /**
         * @return UserData object that represents user's last name.
         */
        static UserData lastName(const std::string& value);
        //@}
        /**
         * @brief Set parent account UUID.
         */
        UserData& accountId (const std::string& accountId);
        /**
         * @brief Get parent account UUID.
         */
        std::string accountId () const;
        /**
         * @brief Set parent public key UUID.
         */
        UserData& publicKeyId (const std::string& publicKeyId);
        /**
         * @brief Get parent public key UUID.
         */
        std::string publicKeyId () const;
        /**
         * @brief Set user data UUID.
         */
        UserData& userDataId (const std::string& userDataId);
        /**
         * @brief Get user data UUID.
         */
        std::string userDataId () const;
        /**
         * @brief Set user data class, i.e. "user_id", "user_info".
         */
        UserData& className(const std::string& className);
        /**
         * @brief Get user data class.
         */
        std::string className() const;
        /**
         * @brief Set user data type, i.e. "email", "phone", "fax", "first_name", etc.
         */
        UserData& type(const std::string& type);
        /**
         * @brief Get user data type.
         */
        std::string type() const;
        /**
         * @brief Set user data value.
         */
        UserData& value(const std::string& value);
        /**
         * @brief Get user data value.
         */
        std::string value() const;
        /**
         * @brief Set user data flag "is confirmed".
         */
        UserData& isConfirmed(bool isConfirmed);
        /**
         * @brief Get user data flag "is confirmed".
         */
        bool isConfirmed() const;
        /**
         * @brief Equality comparison.
         */
         bool operator==(const UserData& other);
        /**
         * @brief Non equality comparison.
         */
         bool operator!=(const UserData& other);
    private:
        std::string accountId_;
        std::string publicKeyId_;
        std::string userDataId_;
        std::string className_;
        std::string type_;
        std::string value_;
        bool isConfirmed_;
    };
}}}}

#endif /* VIRGIL_SDK_PRIVATE_KEYS_MODEL_USER_DATA_H */
