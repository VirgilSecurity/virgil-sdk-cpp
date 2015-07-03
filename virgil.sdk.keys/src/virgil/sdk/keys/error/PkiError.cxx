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

#include <virgil/sdk/keys/error/PkiError.h>
using virgil::sdk::keys::error::PkiError;

#include <sstream>

PkiError::PkiError(PkiError::Action action, Response::StatusCode statusCode,
        unsigned int errorCode)
        : runtime_error(formatMessage(action, statusCode, errorCode)) {
}


std::string PkiError::formatMessage(PkiError::Action action, Response::StatusCode statusCode,
        unsigned int errorCode) noexcept {

    std::ostringstream message;

    message << "Failed to ";
    switch (action) {
    case PkiError::Action::PUBLIC_KEY_ADD:
        message << "add public key.";
        break;
    case PkiError::Action::PUBLIC_KEY_GET:
        message << "get public key.";
        break;
    case PkiError::Action::PUBLIC_KEY_SEARCH:
        message << "search public key.";
        break;
    case PkiError::Action::USER_DATA_ADD:
        message << "add user data.";
        break;
    case PkiError::Action::USER_DATA_GET:
        message << "get user data.";
        break;
    case PkiError::Action::USER_DATA_SEARCH:
        message << "search user data.";
        break;
    case PkiError::Action::USER_DATA_CONFIRM:
        message << "confirm user data.";
        break;
    case PkiError::Action::USER_DATA_CONFIRM_RESEND:
        message << "resend user data confirmation.";
        break;
    default:
        message << "make unknown action.";
        break;
    }

    switch (statusCode) {
    case Response::StatusCode::REQUEST_ERROR:
        message << " Request error.";
        break;
    case Response::StatusCode::AUTHORIZATION_ERROR:
        message << " Authorization error.";
        break;
    case Response::StatusCode::ENTITY_NOT_FOUND:
        message << " Entity not found.";
        break;
    case Response::StatusCode::METHOD_NOT_ALLOWED:
        message << " Method not allowed.";
        break;
    case Response::StatusCode::SERVER_ERROR:
        message << " Server error.";
        break;
    default:
        message << " Unknown error.";
        break;
    }

    switch (errorCode) {
    case 10000:
        message << " Internal application error.";
        break;
    case 10001:
        message << " Application kernel error.";
        break;
    case 10010:
        message << " Internal application error.";
        break;
    case 10011:
        message << " Internal application error.";
        break;
    case 10012:
        message << " Internal application error.";
        break;
    case 10100:
        message << " JSON specified as a request body is invalid.";
        break;
    case 10200:
        message << " Guid specified is expired already.";
        break;
    case 10201:
        message << " The Guid specified is invalid.";
        break;
    case 10202:
        message << " The Authorization header was not specified.";
        break;
    case 10203:
        message << " Public key header not specified or incorrect.";
        break;
    case 10204:
        message << " The signed digest specified is incorrect.";
        break;
    case 20000:
        message << " Account object not found for id specified.";
        break;
    case 20100:
        message << " Public key object not found for id specified.";
        break;
    case 20101:
        message << " Public key invalid.";
        break;
    case 20102:
        message << " Public key not specified.";
        break;
    case 20103:
        message << " Public key must be base64-encoded string.";
        break;
    case 20200:
        message << " UserData object not found for id specified.";
        break;
    case 20201:
        message << " UserData type specified is invalid.";
        break;
    case 20202:
        message << " UserData type specified for user identity is invalid.";
        break;
    case 20203:
        message << " Domain specified for domain identity is invalid.";
        break;
    case 20204:
        message << " Email specified for email identity is invalid.";
        break;
    case 20205:
        message << " Phone specified for phone identity is invalid.";
        break;
    case 20206:
        message << " Fax specified for fax identity is invalid.";
        break;
    case 20207:
        message << " Application specified for application identity is invalid.";
        break;
    case 20208:
        message << " Mac address specified for mac address identity is invalid.";
        break;
    case 20210:
        message << " UserData integrity constraint violation.";
        break;
    case 20211:
        message << " UserData confirmation entity not found by code specified.";
        break;
    case 20212:
        message << " UserData confirmation code invalid.";
        break;
    case 20213:
        message << " UserData was already confirmed and does not need further confirmation.";
        break;
    case 20214:
        message << " UserData class specified is invalid.";
        break;
    case 20300:
        message << " User info data validation failed. Name is invalid.";
        break;
    default:
        // Do nothing.
        break;
    }

    return message.str();
}
