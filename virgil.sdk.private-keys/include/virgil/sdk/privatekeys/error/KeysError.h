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

#ifndef VIRGIL_SDK_PRIVATE_KEYS_KEYS_ERROR_H
#define VIRGIL_SDK_PRIVATE_KEYS_KEYS_ERROR_H

#include <stdexcept>
#include <string>

#include <virgil/sdk/privatekeys/http/Response.h>


namespace virgil { namespace sdk { namespace privatekeys { namespace error {
    /**
     * @brief Virgil Private Keys service exception.
     *
     * This class defines the type of object thrown as exception
     *     to report errors that occurs during Virgil Private Keys Service communication.
     */
    class KeysError final : public std::runtime_error {
    public:
        /**
         * @brief Define constant for undefined error code.
         */
        static const unsigned int kUndefinedErrorCode = 0;
        /**
         * @brief Defines which action trigger an error.
         */
        enum class Action {
            GET_AUTH_TOKEN,
            CREATE_CONTAINER,
            GET_CONTAINER_DETAILS,
            UPDATE_CONTAINER_INFORMATION,
            RESET_CONTAINER_PASSWORD,
            CONFIRM_OPERATION,
            DELETE_CONTAINER,
            ADD_PRIVATE_KEY,
            GET_PRIVATE_KEY,
            DELETE_PRIVATE_KEY
        };
        /**
         * @brief Initialize exception.
         * @param action - defines which action trigger an error.
         * @param statusCode - HTTP response status code.
         * @param errorCode - specific Virgil Private Keys service error code.
         */
        KeysError(KeysError::Action action, virgil::sdk::privatekeys::http::Response::StatusCode statusCode,
                unsigned int errorCode = kUndefinedErrorCode);
    private:
        /**
         * @brief Create formatted error message.
         */
        std::string formatMessage(KeysError::Action action, virgil::sdk::privatekeys::http::Response::StatusCode statusCode,
                unsigned int errorCode) noexcept;
    };
}}}}

#endif /* VIRGIL_SDK_PRIVATE_KEYS_KEYS_ERROR_H */
