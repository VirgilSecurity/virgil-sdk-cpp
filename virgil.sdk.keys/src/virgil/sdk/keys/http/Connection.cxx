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

#include <virgil/sdk/keys/http/Connection.h>
using virgil::sdk::keys::http::Connection;

#include <virgil/sdk/keys/http/Request.h>
using virgil::sdk::keys::http::Request;
#include <virgil/sdk/keys/http/Response.h>
using virgil::sdk::keys::http::Response;

#include <virgil/sdk/keys/util/JsonKey.h>
using virgil::sdk::keys::util::JsonKey;

#include <stdexcept>

#include <json.hpp>
using json = nlohmann::json;

#include <restless.hpp>
using HttpRequest = asoni::Handle;

Response Connection::send(const Request& request) {
    // Construct URI
    std::string uri = request.baseAddress().empty() ?
            this->baseAddress() + request.uri() : request.uri();
    // Add custom field to the header
    auto header = request.header();
    if (header.find("X-VIRGIL-APP-TOKEN") == header.end()) {
        header["X-VIRGIL-APP-TOKEN"] = appToken();
    }
    // Make Request
    HttpRequest httpRequest;
    httpRequest.header(header).content(request.contentType(), request.body());
    switch (request.method()) {
        case Request::Method::GET:
            httpRequest.get(uri);
            break;
        case Request::Method::POST:
            httpRequest.post(uri);
            break;
        case Request::Method::PUT:
            httpRequest.put(uri);
            break;
        case Request::Method::DELETE:
            httpRequest.del(uri);
            break;
        default:
            throw std::logic_error("Unknown HTTP method.");
    }
    // Execute
    auto httpResponse = httpRequest.exec();
    // Make response
    Response response;
    try {
        response.statusCodeRaw(httpResponse.code);
    } catch (const std::logic_error&) {
        throw std::runtime_error(httpResponse.body);
    }
    return response.header(httpResponse.headers).body(httpResponse.body);
}

void Connection::checkResponseError(const Response& response, PkiError::Action action) {
    if (response.fail()) {
        json error = json::parse(response.body());
        json errorCode = error[JsonKey::error][JsonKey::code];
        throw PkiError(action, response.statusCode(),
                errorCode.is_number() ? errorCode.get<unsigned int>() : PkiError::undefinedErrorCode);
    }
}
