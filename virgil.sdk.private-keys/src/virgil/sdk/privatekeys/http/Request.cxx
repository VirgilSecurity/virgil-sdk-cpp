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

#include <sstream>

#include <virgil/sdk/privatekeys/http/Request.h>

using virgil::sdk::privatekeys::http::Request;

static std::string normalize_base_address(const std::string& baseAddress) {
    if (!baseAddress.empty() && baseAddress.back() == '/') {
        return baseAddress.substr(0, baseAddress.size() - 1);
    }
    return baseAddress;
}

Request& Request::baseAddress (const std::string& baseAddress) {
    baseAddress_ = normalize_base_address(baseAddress);
    return *this;
}

std::string Request::baseAddress () const {
    return baseAddress_;
}

Request& Request::body (const std::string& body) {
    body_ = body;
    return *this;
}

std::string Request::body () const {
    return body_;
}

Request& Request::contentType (const std::string& contentType) {
    contentType_ = contentType;
    return *this;
}

std::string Request::contentType () const {
    return contentType_;
}

Request& Request::endpoint (const std::string& endpoint) {
    endPoint_ = endpoint;
    return *this;
}

std::string Request::endpoint () const {
    return endPoint_;
}

Request& Request::header (const Request::Header& header) {
    header_ = header;
    return *this;
}

Request::Header Request::header () const {
    return header_;
}

Request& Request::parameters (const Request::Parameters& parameters) {
    parameters_ = parameters;
    return *this;
}

Request::Parameters Request::parameters () const {
    return parameters_;
}


std::string Request::uri() const {
    std::ostringstream uri;
    uri << baseAddress() << endpoint() << "?";
    for (auto param : parameters()) {
        uri << "&" << param.first << "=" << param.second;
    }
    return uri.str();
}

Request& Request::method (const Request::Method& method) {
    method_ = method;
    return *this;
}

Request::Method Request::method () const {
    return method_;
}

Request& Request::get () {
    return method(Method::GET);
}

Request& Request::post () {
    return method(Method::POST);
}

Request& Request::put () {
    return method(Method::PUT);
}

Request& Request::del () {
    return method(Method::DEL);
}
