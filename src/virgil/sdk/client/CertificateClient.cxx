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

#include <nlohman/json.hpp>

#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/Error.h>
#include <virgil/sdk/client/ClientConnection.h>
#include <virgil/sdk/client/CertificateClient.h>
#include <virgil/sdk/endpoints/CertificateEndpointUri.h>
#include <virgil/sdk/http/Request.h>
#include <virgil/sdk/http/Response.h>
#include <virgil/sdk/io/Marshaller.h>
#include <virgil/sdk/dto/ValidatedIdentity.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/util/uuid.h>

using json = nlohmann::json;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::Credentials;
using virgil::sdk::Error;
using virgil::sdk::client::ClientConnection;
using virgil::sdk::client::Client;
using virgil::sdk::client::CertificateClient;
using virgil::sdk::endpoints::CertificateEndpointUri;
using virgil::sdk::http::Request;
using virgil::sdk::http::Response;
using virgil::sdk::io::Marshaller;
using virgil::sdk::models::CardModel;
using virgil::sdk::models::CRLModel;
using virgil::sdk::models::CertificateModel;
using virgil::sdk::dto::ValidatedIdentity;
using virgil::sdk::dto::Identity;
using virgil::sdk::util::JsonKey;
using virgil::sdk::util::uuid;

CertificateModel CertificateClient::create(const virgil::sdk::dto::ValidatedIdentity& validatedIdentity,
                                           const virgil::crypto::VirgilByteArray& publicKey,
                                           const virgil::sdk::Credentials& credentials,
                                           const std::map<std::string, std::string>& customData) {
    json jsonPayload = {{JsonKey::publicKey, VirgilBase64::encode(publicKey)},
        {JsonKey::identity,
            {{JsonKey::type, validatedIdentity.getType()},
                {JsonKey::value, validatedIdentity.getValue()},
                {JsonKey::validationToken, validatedIdentity.getToken()}}}};
    json jsonCustomData(customData);
    jsonPayload[JsonKey::data] = jsonCustomData;
    
    ClientConnection connection(getAccessToken());
    Request request = Request()
    .post()
    .baseAddress(getBaseServiceUri())
    .endpoint(CertificateEndpointUri::create())
    .body(jsonPayload.dump());
    
    Request signRequest = connection.signRequest(credentials, request);
    
    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CERTIFICATE_CREATE);
    verifyResponse(response);
    return Marshaller<CertificateModel>::fromJson(response.body());
}

void CertificateClient::revoke(const std::string & certificateId,
                               const virgil::sdk::dto::ValidatedIdentity& validatedIdentity,
                               const virgil::sdk::Credentials& credentials) {
    json payload = {{JsonKey::identity,
        {{JsonKey::type, validatedIdentity.getType()},
            {JsonKey::value, validatedIdentity.getValue()},
            {JsonKey::validationToken, validatedIdentity.getToken()}}}};
    
    Request request = Request()
    .del()
    .baseAddress(getBaseServiceUri())
    .endpoint(CertificateEndpointUri::revoke(certificateId))
    .body(payload.dump());
    
    ClientConnection connection(getAccessToken());
    Request signRequest = connection.signRequest(certificateId, credentials, request);
    
    Response response = connection.send(signRequest);
    connection.checkResponseError(response, Error::Action::VIRGIL_CERTIFICATE_REVOKE);
    verifyResponse(response);
}

CertificateModel CertificateClient::pull(const virgil::sdk::dto::Identity & identity) {
    json payload = {{JsonKey::value, identity.getValue()},
        {JsonKey::type, identity.getType()}};
    
    Request request = Request()
    .post()
    .baseAddress(getBaseServiceUri())
    .endpoint(CertificateEndpointUri::pull())
    .body(payload.dump());
    
    ClientConnection connection(getAccessToken());
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CERTIFICATE_PULL);
    verifyResponse(response);
    return Marshaller<CertificateModel>::fromJson(response.body());
}

CertificateModel CertificateClient::pullRootCertificate() {
    Request request = Request()
    .post()
    .baseAddress(getBaseServiceUri())
    .endpoint(CertificateEndpointUri::pullRootCertificate())
    .body("{}");
    
    ClientConnection connection(getAccessToken());
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CERTIFICATE_PULL_ROOT);
    verifyResponse(response);
    return Marshaller<CertificateModel>::fromJson(response.body());
}

CRLModel CertificateClient::getCRL() {
    Request request = Request()
    .get()
    .baseAddress(getBaseServiceUri())
    .endpoint(CertificateEndpointUri::crl());
    
    ClientConnection connection(getAccessToken());
    Response response = connection.send(request);
    connection.checkResponseError(response, Error::Action::VIRGIL_CERTIFICATE_GET_CRL);
    verifyResponse(response);
    return Marshaller<CRLModel>::fromJson(response.body());
}
