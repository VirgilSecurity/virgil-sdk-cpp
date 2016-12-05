/**
 * Copyright (C) 2016 Virgil Security Inc.
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

#include <virgil/sdk/client/models/errors/VirgilError.h>

using virgil::sdk::client::models::errors::VirgilError;

VirgilError::VirgilError(int virgilErrorCode) : virgilErrorCode_(virgilErrorCode) {
    switch (virgilErrorCode) {
        case 20300:
            errorMsg_ = "The Virgil access token or token header was not specified or is invalid";
            break;
        case 20301:
            errorMsg_ = "The Virgil authenticator service responded with an error";
            break;
        case 20302:
            errorMsg_ = "The Virgil access token validation has failed on the Virgil Authenticator service";
            break;
        case 20303:
            errorMsg_ = "The application was not found for the access token";
            break;
        case 20400:
            errorMsg_ = "Request sign is invalid or missing";
            break;
        case 20401:
            errorMsg_ = "Request sign header is missing";
            break;

        case 20500:
            errorMsg_ = "The Virgil Card is not available in this application";
            break;

        case 30000:
            errorMsg_ = "JSON specified as a request is invalid";
            break;
        case 30010:
            errorMsg_ = "A data inconsistency error";
            break;
        case 30100:
            errorMsg_ = "Global Virgil Card identity type is invalid, because it can be only an 'email'";
            break;
        case 30101:
            errorMsg_ = "Virgil Card scope must be either 'global' or 'application'";
            break;
        case 30102:
            errorMsg_ = "Virgil Card id validation failed";
            break;
        case 30103:
            errorMsg_ = "Virgil Card data parameter cannot contain more than 16 entries";
            break;
        case 30104:
            errorMsg_ = "Virgil Card info parameter cannot be empty if specified and must contain 'device' and/or 'device_name' key";
            break;
        case 30105:
            errorMsg_ = "Virgil Card info parameters length validation failed. The value must be a string and mustn't exceed 256 characters";
            break;
        case 30106:
            errorMsg_ = "Virgil Card data parameter must be an associative array (https://en.wikipedia.org/wiki/Associative_array)";
            break;
        case 30107:
            errorMsg_ = "A CSR parameter (content_snapshot) parameter is missing or is incorrect";
            break;
        case 30111:
            errorMsg_ = "Virgil Card identities passed to search endpoint must be a list of non-empty strings";
            break;
        case 30113:
            errorMsg_ = "Virgil Card identity type is invalid";
            break;
        case 30114:
            errorMsg_ = "Segregated Virgil Card custom identity value must be a not empty string";
            break;
        case 30115:
            errorMsg_ = "Virgil Card identity email is invalid";
            break;
        case 30116:
            errorMsg_ = "Virgil Card identity application is invalid";
            break;
        case 30117:
            errorMsg_ = "Public key length is invalid. It goes from 16 to 2048 bytes";
            break;
        case 30118:
            errorMsg_ = "Public key must be base64-encoded string";
            break;
        case 30119:
            errorMsg_ = "Virgil Card data parameter must be a key/value list of strings";
            break;
        case 30120:
            errorMsg_ = "Virgil Card data parameters must be strings";
            break;
        case 30121:
            errorMsg_ = "Virgil Card custom data entry value length validation failed. It mustn't exceed 256 characters";
            break;
        case 30122:
            errorMsg_ = "Identity validation token is invalid";
            break;
        case 30123:
            errorMsg_ = "SCR signs list parameter is missing or is invalid";
            break;
        case 30126:
            errorMsg_ = "SCR sign item signer card id is irrelevant and doesn't match Virgil Card id or Application Id";
            break;
        case 30127:
            errorMsg_ = "SCR sign item signed digest is invalid for the Virgil Card public key";
            break;
        case 30128:
            errorMsg_ = "SCR sign item signed digest is invalid or missing for the application";
            break;
        case 30131:
            errorMsg_ = "Virgil Card id specified in the request body must match with the one passed in the URL";
            break;
        case 30134:
            errorMsg_ = "Virgil Card data parameters key must be aplphanumerical";
            break;
        case 30135:
            errorMsg_ = "Virgil Card validation token must be an object with value parameter";
            break;
        case 30136:
            errorMsg_ = "SCR sign item signed digest is invalid for the virgil identity service";
            break;
        case 30137:
            errorMsg_ = "Global Virigl Card cannot be created unconfirmed (which means that Virgil Identity service sign is mandatory)";
            break;
        case 30138:
            errorMsg_ = "Virigl Card with the same fingerprint exists already";
            break;
        case 30139:
            errorMsg_ = "Virigl Card revocation reason isn't specified or is invalid";
            break;

        default:
            errorMsg_ = "Unknown error";
            break;
    }
}

