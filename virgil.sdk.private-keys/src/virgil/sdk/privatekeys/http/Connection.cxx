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

#include <stdexcept>

#include <restless.hpp>

#include <virgil/sdk/privatekeys/http/Connection.h>
#include <virgil/sdk/privatekeys/http/Request.h>
#include <virgil/sdk/privatekeys/http/Response.h>

using HttpRequest = asoni::Handle;

using virgil::sdk::privatekeys::http::Connection;
using virgil::sdk::privatekeys::http::Request;
using virgil::sdk::privatekeys::http::Response;


Response Connection::send(const Request& request) {
    // Make Request
    HttpRequest httpRequest;
    httpRequest.header(request.header()).content(request.contentType(), request.body());
    switch (request.method()) {
        case Request::Method::GET:
            httpRequest.get(request.uri());
            break;
        case Request::Method::POST:
            httpRequest.post(request.uri());
            break;
        case Request::Method::PUT:
            httpRequest.put(request.uri());
            break;
        case Request::Method::DEL:
            httpRequest.del(request.uri());
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
