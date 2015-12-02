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

#include <virgil/sdk/keys/error/KeysError.h>

#include <string>
#include <map>

using virgil::sdk::keys::error::KeysError;
using virgil::sdk::keys::http::Response;

const unsigned int KeysError::kUndefinedErrorCode;

KeysError::KeysError(KeysError::Action action, Response::StatusCode statusCode,
        unsigned int errorCode)
        : runtime_error(formatMessage(action, statusCode, errorCode)) {
}

static std::string actionStr(KeysError::Action action) {
    static std::map<KeysError::Action, std::string> code2str = {
        { KeysError::Action::PUBLIC_KEY_ADD, "add public key." },
        { KeysError::Action::PUBLIC_KEY_GET, "get public key." },
        { KeysError::Action::PUBLIC_KEY_UPDATE, "update public key." },
        { KeysError::Action::PUBLIC_KEY_DELETE, "delete public key." },
        { KeysError::Action::PUBLIC_KEY_CONFIRM_DELETE, "confirm delete public key." },
        { KeysError::Action::PUBLIC_KEY_RESET, "reset public key." },
        { KeysError::Action::PUBLIC_KEY_CONFIRM_RESET, "confirm reset public key." },
        { KeysError::Action::PUBLIC_KEY_GRAB, "grab public key." },
        { KeysError::Action::USER_DATA_ADD, "add user data." },
        { KeysError::Action::USER_DATA_DELETE, "delete user data." },
        { KeysError::Action::USER_DATA_CONFIRM, "confirm user data." },
        { KeysError::Action::USER_DATA_CONFIRM_RESEND, "resend user data confirmation." }
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
        { 10100, "JSON specified as a request is invalid." },
        { 10200, "The request_sign_uuid parameter was already used for another request." },
        { 10201, "The request_sign_uuid parameter is invalid." },
        { 10202, "The request sign header not found." },
        { 10203, "The Public Key header not specified or incorrect." },
        { 10204, "The request sign specified is incorrect." },
        { 10207, "The Public Key UUID passed in header was not confirmed yet." },
        { 10209, "Public Key specified in authorization header is registered for another application." },
        { 10210, "Public Key value in request body for POST /public-key endpoint must be base64 encoded value." },
        { 10205, "The Virgil application token not specified or invalid." },
        { 10206, "The Virgil statistics application error." },
        { 10208, "Public Key value required in request body." },
        { 20000, "Account object not found for id specified." },
        { 20100, "Public Key object not found for id specified." },
        { 20101, "Public key length invalid." },
        { 20102, "Public key not specified." },
        { 20103, "Public key must be base64-encoded string." },
        { 20104, "Public key must contain confirmed UserData entities." },
        { 20105, "Public key must contain at least one 'user ID' entry." },
        { 20107, "There is UDID registered for current application already." },
        { 20108, "UDIDs specified are registered for several accounts." },
        { 20110, "Public key is not found for any application." },
        { 20111, "Public key is found for another application." },
        { 20112, "Public key is registered for another application." },
        { 20113, "Sign verification failed for request UUID parameter in PUT /public-key." },
        { 20200, "User Data object not found for id specified." },
        { 20202, "User Data type specified as user identity is invalid." },
        { 20203, "Domain value specified for the domain identity is invalid." },
        { 20204, "Email value specified for the email identity is invalid." },
        { 20205, "Phone value specified for the phone identity is invalid." },
        { 20210, "User Data integrity constraint violation." },
        { 20211, "User Data confirmation entity not found." },
        { 20212, "User Data confirmation token invalid." },
        { 20213, "User Data was already confirmed and does not need further confirmation." },
        { 20214, "User Data class specified is invalid." },
        { 20215, "Domain value specified for the domain identity is invalid." },
        { 20216, "This user id had been confirmed earlier." },
        { 20217, "The user data is not confirmed yet." },
        { 20218, "The user data value is required." },
        { 20300, "User info data validation failed." }
    };
    if (errorCode == KeysError::kUndefinedErrorCode) {
        return "";
    }
    auto message = code2str.find(errorCode);
    return message != code2str.end() ? message->second : "Unknown error.";
}

std::string KeysError::formatMessage(KeysError::Action action, Response::StatusCode statusCode,
        unsigned int errorCode) noexcept {
    return actionStr(action) + " " + statusCodeStr(statusCode) + " " + errorCodeStr(errorCode);
}
