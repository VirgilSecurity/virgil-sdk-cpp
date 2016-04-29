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

#include <virgil/sdk/Error.h>

#include <string>
#include <map>

using virgil::sdk::Error;
using virgil::sdk::http::Response;

const unsigned int Error::kUndefinedErrorCode;

Error::Error(Error::Action action, Response::StatusCode statusCode, unsigned int errorCode)
        : runtime_error(formatMessage(action, statusCode, errorCode)) {
}

static std::string actionStr(Error::Action action) {
    static std::map<Error::Action, std::string> code2str = {
        {Error::Action::PUBLIC_KEY_GET_SIGN, "get Virgil Cards."},
        {Error::Action::PUBLIC_KEY_GET_UNSIGN, "get a Public Key."},
        {Error::Action::PUBLIC_KEY_REVOKE, "revoke a Public Key."},

        {Error::Action::VIRGIL_CARD_CREATE, "create a Virgil Card."},
        {Error::Action::VIRGIL_CARD_GET, "get a Virgil Card."},
        {Error::Action::VIRGIL_CARD_SIGN, "sign the Virgil Card."},
        {Error::Action::VIRGIL_CARD_UNSIGN, "unsign the Virgil Card."},
        {Error::Action::VIRGIL_CARD_SEARCH, "search a Virgil Card."},
        {Error::Action::VIRGIL_CARD_SEARCH_APP, "search an Application Virgil Card."},
        {Error::Action::VIRGIL_CARD_REVOKE, "revoke a Virgil Card."},

        {Error::Action::PRIVATE_KEY_ADD, "load a Private Key into the Private"
                                         " Keys Service storage."},
        {Error::Action::PRIVATE_KEY_GET, "get an existing private key."},
        {Error::Action::PRIVATE_KEY_DEL, "delete a Private Key."},
        {Error::Action::IDENTITY_VERIFY, "verify the Identity."},
        {Error::Action::IDENTITY_CONFIRM, "confirms the Identity."},
        {Error::Action::IDENTITY_VALIDATE, "validates the passed token."}};
    auto message = code2str.find(action);
    return "Failed action: " + (message != code2str.end() ? message->second : "unknown.");
}

static std::string statusCodeStr(Response::StatusCode statusCode) {
    static std::map<Response::StatusCode, std::string> code2str = {
        {Response::StatusCode::REQUEST_ERROR, "request error."},
        {Response::StatusCode::AUTHORIZATION_ERROR, "authorization error."},
        {Response::StatusCode::ENTITY_NOT_FOUND, "entity not found."},
        {Response::StatusCode::METHOD_NOT_ALLOWED, "method not allowed."},
        {Response::StatusCode::SERVER_ERROR, "server error."}};
    auto message = code2str.find(statusCode);
    return "HTTP response: " + (message != code2str.end() ? message->second : "unknown.");
}

static std::string errorCodeStr(unsigned int errorCode) {
    static std::map<unsigned int, std::string> code2str = {
        {10000, "Internal application error."},
        {10010, "Controller was not found."},
        {10020, "Action was not found."},

        {40000, "JSON specified as a request body is invalid."},
        {40100, "Identity type is invalid."},
        {40110, "Identity's ttl is invalid."},
        {40120, "Identity's ctl is invalid."},
        {40130, "Identity's token parameter is missing."},
        {40140, "Identity's token doesn't match parameters."},
        {40150, "Identity's token has expired."},
        {40160, "Identity's token cannot be decrypted."},
        {40170, "Identity's token parameter is invalid."},
        {40180, "Identity is not unconfirmed."},
        {40190, "Hash to be signed parameter is invalid."},
        {40200, "Email identity value validation failed."},
        {40210, "Identity's confirmation code is invalid."},
        {40300, "Application value is invalid."},
        {40310, "Application's signed message is invalid."},
        {41000, "Identity entity was not found."},
        {41010, "Identity's confirmation period has expired."},

        {20100, "The request ID header was used already."},
        {20101, "The request ID header is invalid."},
        {20200, "The request sing header not found."},
        {20201, "The Virgil Card ID header not specified or incorrect."},
        {20202, "The request sign header is invalid."},
        {20203, "Public Key value is required in request body."},
        {20204, "Public Key value in request body must be base64 encoded value."},
        {20205, "Public Key IDs in URL part and public key for the Virgil Card"
                " retrieved from X-VIRGIL-REQUEST-SIGN-VIRGIL-CARD-ID header must match."},
        {20206, "The public key id in the request body is invalid."},
        {20208, "Virgil card ids in url and authentication header must match."},
        {20300, "The Virgil application token was not specified or invalid."},
        {20301, "The Virgil statistics application error."},

        {30000, "JSON specified as a request body is invalid."},
        {30100, "Public Key ID is invalid."},
        {30101, "Public key length invalid."},
        {30102, "Public key must be base64-encoded string."},
        {30201, "Identity type is invalid. Valid types are: 'email', 'application'."},
        {30202, "Email value specified for the email identity is invalid."},
        {30203, "Cannot create unconfirmed application identity."},
        {30204, "Application value specified for the application identity is invalid."},
        {30205, "Custom identity validation failed."},
        {30300, "Signed Virgil Card not found by UUID provided."},
        {30301, "Virgil Card's signs list contains an item with invalid signed_id value."},
        {30302, "Virgil Card's one of sined digests is invalid."},
        {30303, "Virgil Card's data parameters must be strings."},
        {30304, "Virgil Card's data parameters must be an array of strings."},
        {30305, "Virgil Card custom data entry value length validation failed."},
        {30306, "Virgil Card cannot sign itself."},
        {30400, "Sign object not found for id specified."},
        {30402, "The signed digest value is invalid."},
        {30403, "Sign Signed digest must be base64 encoded string."},
        {30404, "Cannot save the Sign because it exists already."},
        {31000, "Value search parameter is mandatory."},
        {31010, "Search value parameter is mandatory for the application search."},
        {31020, "Virgil Card's signs parameter must be an array."},
        {31030, "Identity validation token is invalid."},
        {31040, "Virgil Card revokation parameters do not match Virgil Card's identity."},
        {31050, "Virgil Identity service error."},
        {31051, "Custom identity's validation token is incorrect."},
        {31052, "Custom identity's unique id was used alreaady."},
        {31053, "Custom identity's validation token is malformed."},
        {31060, "Identities parameter is invalid."},
        {31070, "Identity validation failed."},

        {20000, "Request wrongly encoded."},
        {20010, "Request JSON invalid."},
        {20020, "Request 'response_password' parameter invalid."},

        {30010, "Private Key not specified."},
        {30020, "Private Key not base64 encoded."},

        {40000, "Virgil Card ID not specified."},
        {40010, "Virgil Card ID has incorrect format."},
        {40020, "Virgil Card ID not found."},
        {40030, "Virgil Card ID already exists."},
        {40040, "Virgil Card ID not found in Public Key service."},
        {40050, "Virgil Card ID not found for provided Identity"},

        {50000, "Request Sign UUID not specified."},
        {50010, "Request Sign UUID has wrong format."},
        {50020, "Request Sign UUID already exists."},
        {50030, "Request Sign is incorrect."},

        {60000, "Identity not specified."},
        {60010, "Identity Type not specified."},
        {60020, "Identity Value not specified."},
        {60030, "Identity Token not specified."},

        {90000, "Identity validation under RA service failed."},
        {90010, "Access Token validation under Stats service failed."}

    };
    if (errorCode == Error::kUndefinedErrorCode) {
        return "";
    }
    auto message = code2str.find(errorCode);
    return message != code2str.end() ? message->second : "Unknown error.";
}

std::string Error::formatMessage(Error::Action action, Response::StatusCode statusCode,
                                 unsigned int errorCode) noexcept {
    return actionStr(action) + " " + statusCodeStr(statusCode) + " " + errorCodeStr(errorCode);
}
