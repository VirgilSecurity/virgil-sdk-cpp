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

#ifndef VIRGIL_SDK_KEYS_MODEL_USER_DATA_TYPE_H
#define VIRGIL_SDK_KEYS_MODEL_USER_DATA_TYPE_H

#include <string>

namespace virgil { namespace sdk { namespace keys { namespace model {
    /**
     * @brief Contains string representation of "Virgil User Data" class type.
     */
    class UserDataType {
    public:
        /**
         * @name User identifier types.
         */
        //@{
        /**
         * @property emailId
         * @brief Represents user identifer type - email.
         */
        static const std::string emailId;
        /**
         * @property phoneId
         * @brief Represents user identifer type - phone.
         */
        static const std::string phoneId;
        /**
         * @property applicationId
         * @brief Represents user identifer type - application.
         */
        static const std::string applicationId;
        /**
         * @property domainId
         * @brief Represents user identifer type - domain.
         */
        static const std::string domainId;
        //@}
        /**
         * @name User info types.
         */
        //@{
        /**
         * @property firstNameInfo
         * @brief Represents user info type - first name.
         */
        static const std::string firstNameInfo;
        /**
         * @property lastNameInfo
         * @brief Represents user info type - last name.
         */
        static const std::string lastNameInfo;
        //@}
    };
}}}}

#endif /* VIRGIL_SDK_KEYS_MODEL_USER_DATA_TYPE_H */
