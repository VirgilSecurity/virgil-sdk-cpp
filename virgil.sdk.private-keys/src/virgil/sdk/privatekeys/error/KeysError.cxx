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

#include <map>
#include <string>

#include <virgil/sdk/privatekeys/error/KeysError.h>

using virgil::sdk::privatekeys::error::KeysError;
using virgil::sdk::privatekeys::http::Response;

KeysError::KeysError(KeysError::Action action, Response::StatusCode statusCode,
        unsigned int errorCode)
        : runtime_error(formatMessage(action, statusCode, errorCode)) {
}

static std::string actionStr(KeysError::Action action) {
    static std::map<KeysError::Action, std::string> code2str = {
        { KeysError::Action::GET_AUTH_TOKEN, "get authentication token." },
        { KeysError::Action::CREATE_CONTAINER, "create Container information." },
        { KeysError::Action::GET_CONTAINER_DETAILS, "get container information by Public Key IUUIDD." },
        { KeysError::Action::UPDATE_CONTAINER_INFORMATION, "update container information." },
        { KeysError::Action::RESET_CONTAINER_PASSWORD, "reset container password." },
        { KeysError::Action::CONFIRM_OPERATION, "confirm password token and re-encrypt Private Key data with the new password." },
        { KeysError::Action::DELETE_CONTAINER, "delete container object by Public Key UUID." },
        { KeysError::Action::ADD_PRIVATE_KEY, "push Private Key data to Container." },
        { KeysError::Action::GET_PRIVATE_KEY, "get Private Key data by Public Key UUID." },
        { KeysError::Action::DELETE_PRIVATE_KEY, "delete Private Key data by Public Key UUID." }
    };
    auto message = code2str.find(action);
    return "Failed action: " + (message != code2str.end() ? message->second : "unknown.");
}

static std::string statusCodeStr(Response::StatusCode statusCode) {
    static std::map<Response::StatusCode, std::string> code2str = {
        { Response::StatusCode::REQUEST_ERROR, "request error." },
        { Response::StatusCode::AUTHORIZATION_ERROR, "authorization error." },
        { Response::StatusCode::ENTITY_NOT_FOUND, "entity not found." },
        { Response::StatusCode::METHOD_NOT_ALLOWED, "method not allowed." },
        { Response::StatusCode::SERVER_ERROR, "server error." }
    };
    auto message = code2str.find(statusCode);
    return "HTTP response: " + (message != code2str.end() ? message->second : "unknown.");
}

static std::string errorCodeStr(unsigned int errorCode) {
    static std::map<unsigned int, std::string> code2str = {
        { KeysError::kUndefinedErrorCode, "" },
        { 10001, "Private Keys Service - Internal Application Error: route was not found." },
        { 10002, "Private Keys Service - Internal Application Error: route not allowed." },

        { 20001, "Private Keys Service - Authentication error: password validation failed." },
        { 20002, "Private Keys Service - Authentication error: user data validation failed." },
        { 20003, "Private Keys Service - Authentication error: container was not found." },
        { 20004, "Private Keys Service - Authentication error: token validation failed." },
        { 20005, "Private Keys Service - Authentication error: token not found." },
        { 20006, "Private Keys Service - Authentication error: token has expired." },

        { 30001, "Private Keys Service - Request Sign error: request Sign validation failed." },

        { 40001, "Private Keys Service - Container error: container validation failed." },
        { 40002, "Private Keys Service - Container error: container was not found." },
        { 40003, "Private Keys Service - Container error: container already exists." },
        { 40004, "Private Keys Service - Container error: container password was not specified." },
        { 40005, "Private Keys Service - Container error: container password validation failed." },
        { 40006, "Private Keys Service - Container error: container was not found in PK service." },
        { 40007, "Private Keys Service - Container error: container type validation failed." },

        { 50001, "Private Keys Service - Private Key error: public Key ID validation failed." },
        { 50002, "Private Keys Service - Private Key error: public Key ID was not found." },
        { 50003, "Private Keys Service - Private Key error: public Key ID already exists." },
        { 50004, "Private Keys Service - Private Key error: private key validation failed." },
        { 50005, "Private Keys Service - Private Key error: private key base64 validation failed." },

        { 60001, "Private Keys Service - Verification error: token was not found in request." },
        { 60002, "Private Keys Service - Verification error: user Data validation failed." },
        { 60003, "Private Keys Service - Verification error: container was not found." },
        { 60004, "Private Keys Service - Verification error: verification token hash expired." },

        { 70001, "Private Keys Service - Application Token error: application token invalid." },
        { 70002, "Private Keys Service - Application Token error: application token service error." },

        { 80001, "Private Keys Service - Request Sign UUID error: request parameter validation failed." },
        { 80002, "Private Keys Service - Request Sign UUID error: has already used in another call. Please generate another one." },

        { 10100, "Public Keys Service - JSON specified as a request is invalid." },
        { 10200, "Public Keys Service - The request_sign_uuid parameter was already used for another request." },
        { 10201, "Public Keys Service - The request_sign_uuid parameter is invalid." },
        { 10202, "Public Keys Service - The request sign header not found." },
        { 10203, "Public Keys Service - The Public Key header not specified or incorrect." },
        { 10204, "Public Keys Service - The request sign specified is incorrect." },
        { 10207, "Public Keys Service - The Public Key UUID passed in header was not confirmed yet." },
        { 10209, "Public Keys Service - Public Key specified in authorization header is registered for another application." },
        { 10210, "Public Keys Service - Public Key value in request body for POST /public-key endpoint must be base64 encoded value." },
        { 10205, "Public Keys Service - The Virgil application token not specified or invalid." },
        { 10206, "Public Keys Service - The Virgil statistics application error." },
        { 10208, "Public Keys Service - Public Key value required in request body." },
        { 20000, "Public Keys Service - Account object not found for id specified." },
        { 20100, "Public Keys Service - Public Key object not found for id specified." },
        { 20101, "Public Keys Service - Public key length invalid." },
        { 20102, "Public Keys Service - Public key not specified." },
        { 20103, "Public Keys Service - Public key must be base64-encoded string." },
        { 20104, "Public Keys Service - Public key must contain confirmed UserData entities." },
        { 20105, "Public Keys Service - Public key must contain at least one 'user ID' entry." },
        { 20107, "Public Keys Service - There is UDID registered for current application already." },
        { 20108, "Public Keys Service - UDIDs specified are registered for several accounts." },
        { 20110, "Public Keys Service - Public key is not found for any application." },
        { 20111, "Public Keys Service - Public key is found for another application." },
        { 20112, "Public Keys Service - Public key is registered for another application." },
        { 20113, "Public Keys Service - Sign verification failed for request UUID parameter in PUT /public-key." },
        { 20200, "Public Keys Service - User Data object not found for id specified." },
        { 20202, "Public Keys Service - User Data type specified as user identity is invalid." },
        { 20203, "Public Keys Service - Domain value specified for the domain identity is invalid." },
        { 20204, "Public Keys Service - Email value specified for the email identity is invalid." },
        { 20205, "Public Keys Service - Phone value specified for the phone identity is invalid." },
        { 20210, "Public Keys Service - User Data integrity constraint violation." },
        { 20211, "Public Keys Service - User Data confirmation entity not found." },
        { 20212, "Public Keys Service - User Data confirmation token invalid." },
        { 20213, "Public Keys Service - User Data was already confirmed and does not need further confirmation." },
        { 20214, "Public Keys Service - User Data class specified is invalid." },
        { 20215, "Public Keys Service - Domain value specified for the domain identity is invalid." },
        { 20216, "Public Keys Service - This user id had been confirmed earlier." },
        { 20217, "Public Keys Service - The user data is not confirmed yet." },
        { 20218, "Public Keys Service - The user data value is required." },
        { 20300, "Public Keys Service - User info data validation failed." }

    };
    auto message = code2str.find(errorCode);
    return message != code2str.end() ? message->second : "Unknown error.";
}

std::string KeysError::formatMessage(KeysError::Action action, Response::StatusCode statusCode,
        unsigned int errorCode) noexcept {
    return actionStr(action) + " " + statusCodeStr(statusCode) + " " + errorCodeStr(errorCode);
}
