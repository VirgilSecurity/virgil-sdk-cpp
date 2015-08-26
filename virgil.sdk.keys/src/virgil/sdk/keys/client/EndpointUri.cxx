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

#include <virgil/sdk/keys/client/EndpointUri.h>

using virgil::sdk::keys::client::EndpointUri;

EndpointUri::EndpointUri(EndpointUri::Version uriVersion) : version_(uriVersion) {
}

EndpointUri EndpointUri::v2() {
    return EndpointUri(EndpointUri::Version::V2);
}

EndpointUri::Version EndpointUri::version() const {
    return version_;
}

std::string EndpointUri::publicKeyAdd() const {
    return addVersion("/public-key");
}

std::string EndpointUri::publicKeyGet(const std::string& publicKeyId) const {
    return addVersion("/public-key/" + publicKeyId);
}

std::string EndpointUri::publicKeyUpdate(const std::string& publicKeyId) const {
    return addVersion("/public-key/" + publicKeyId);
}

std::string EndpointUri::publicKeyDelete(const std::string& publicKeyId) const {
    return addVersion("/public-key/" + publicKeyId);
}

std::string EndpointUri::publicKeyGrab() const {
    return addVersion("/public-key/actions/grab");
}

std::string EndpointUri::userDataAdd() const {
    return addVersion("/user-data");
}

std::string EndpointUri::userDataDelete(const std::string& userDataId) const {
    return addVersion("/user-data/" + userDataId);
}

std::string EndpointUri::userDataConfirm(const std::string& userDataId) const {
    return addVersion("/user-data/" + userDataId + "/persist");
}

std::string EndpointUri::userDataResendConfirmation(const std::string& userDataId) const {
    return addVersion("/user-data/" + userDataId + "/actions/resend-confirmation");
}

std::string EndpointUri::addVersion(const std::string& uri) const {
    switch (version()) {
    case EndpointUri::Version::V2:
        return "/v2" + uri;
    }
}
