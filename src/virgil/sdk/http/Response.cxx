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

#include <virgil/sdk/http/Response.h>

#include <stdexcept>
#include <set>

using virgil::sdk::http::Response;

Response& Response::body(const std::string& body) {
    body_ = body;
    return *this;
}

std::string Response::body() const {
    return body_;
}

Response& Response::contentType(const std::string& contentType) {
    contentType_ = contentType;
    return *this;
}

std::string Response::contentType() const {
    return contentType_;
}

Response& Response::header(const Response::Header& header) {
    header_ = header;
    return *this;
}

Response::Header Response::header() const {
    return header_;
}

Response& Response::statusCode(Response::StatusCode statusCode) {
    statusCode_ = statusCode;
    return *this;
}

Response::StatusCode Response::statusCode() const {
    return statusCode_;
}

Response& Response::statusCodeRaw(int code) {
    std::set<int> availableCodes{200, 400, 401, 404, 405, 500, 501};
    if (availableCodes.find(code) != availableCodes.end()) {
        statusCode_ = static_cast<Response::StatusCode>(code);
    } else {
        throw std::logic_error("Given status code is not supported.");
    }
    return *this;
}

int Response::statusCodeRaw() const {
    return static_cast<int>(statusCode_);
}

bool Response::fail() const {
    return statusCode_ != StatusCode::OK;
}
