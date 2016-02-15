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

#include <iostream>
#include <stdexcept>

#include <json.hpp>

#include <restless.hpp>

#include <virgil/sdk/http/Connection.h>

#include <virgil/sdk/http/Request.h>
#include <virgil/sdk/http/Response.h>

using json = nlohmann::json;

using HttpRequest = asoni::Handle;

using virgil::sdk::http::Connection;
using virgil::sdk::http::Request;
using virgil::sdk::http::Response;

void virgilTest(const Request& request) {

    auto headers = request.header();
    for (const auto& header : headers) {
        std::cout << header.first << " : " << header.second << "\n\n";
    }

    std::cout << "uri"
              << "\n" << request.uri() << "\n\n";
    std::cout << "json body\n" << request.body() << "\n\n";

    std::cout << "__________________________________\n\n";
}

void virgilTest(const Response& response) {

    std::cout << "RESPONSE:"
              << "\n\n";

    auto headers = response.header();
    for (const auto& header : headers) {
        std::cout << header.first << " : " << header.second << "\n\n";
    }

    std::cout << "json body\n" << response.body() << "\n\n";

    std::cout << "__________________________________\n\n";
}

Response Connection::send(const Request& request) {
    // Make Request
    HttpRequest httpRequest;
    httpRequest.header(request.header()).content(request.contentType(), request.body());

    switch (request.method()) {
        case Request::Method::GET:
            httpRequest.get(request.uri());
            std::cout << "_____________________________\n";
            std::cout << "Request::Method::GET\n\n";
            virgilTest(request);
            break;
        case Request::Method::POST:
            httpRequest.post(request.uri());
            std::cout << "_____________________________\n";
            std::cout << "Request::Method::POST\n\n";
            virgilTest(request);
            break;
        case Request::Method::PUT:
            httpRequest.put(request.uri());
            std::cout << "_____________________________\n";
            std::cout << "Request::Method::PUT\n\n";
            virgilTest(request);
            break;
        case Request::Method::DEL:
            httpRequest.del(request.uri());
            std::cout << "_____________________________\n";
            std::cout << "Request::Method::DEL\n\n";
            virgilTest(request);
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
        std::cout << "httpResponse.code = " << httpResponse.code << "\n";

    } catch (const std::logic_error&) {
        throw std::runtime_error(httpResponse.body);
    }

    response.header(httpResponse.headers).body(httpResponse.body);

    virgilTest(response);

    return response;
}
