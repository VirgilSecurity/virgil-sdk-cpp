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

#include <virgil/pki/client/EndpointUri.h>
using virgil::pki::client::EndpointUri;

std::string EndpointUri::publicKeyAdd() {
    return "/public-key";
}

std::string EndpointUri::publicKeyGet(const std::string& publicKeyId) {
    return "/public-key/" + publicKeyId;
}

std::string EndpointUri::publicKeySearch() {
    return "/account/actions/search";
}

std::string EndpointUri::userDataAdd() {
    return "/user-data";
}

std::string EndpointUri::userDataGet(const std::string& userDataId) {
    return "/user-data/" + userDataId;
}

std::string EndpointUri::userDataConfirm(const std::string& userDataId) {
    return "/user-data/" + userDataId + "/actions/confirm";
}

std::string EndpointUri::userDataResendConfirm(const std::string& userDataId) {
    return "/user-data/" + userDataId + "/actions/resend-confirmation";
}

std::string EndpointUri::userDataSearch(bool expandPublicKey) {
    if (expandPublicKey) {
        return "/user-data/actions/search/?expand=public_key";
    } else {
        return "/user-data/actions/search";
    }
}
