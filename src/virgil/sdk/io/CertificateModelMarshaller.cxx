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

#include <map>
#include <string>
#include <stdexcept>

#include <nlohman/json.hpp>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/foundation/VirgilBase64.h>

#include <virgil/sdk/io/Marshaller.h>
#include <virgil/sdk/util/JsonKey.h>
#include <virgil/sdk/dto/Identity.h>
#include <virgil/sdk/models/CardModel.h>
#include <virgil/sdk/models/IdentityModel.h>
#include <virgil/sdk/models/CertificateModel.h>

using json = nlohmann::json;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::util::JsonKey;
using virgil::sdk::dto::Identity;
using virgil::sdk::models::CardModel;
using virgil::sdk::models::IdentityModel;
using virgil::sdk::models::CertificateModel;

namespace virgil {
    namespace sdk {
        namespace io {
            /**
             * @brief Marshaller<CertificateModel> specialization.
             */
            template <> class Marshaller<CertificateModel> {
            public:
                static std::string toOriginalJson(const CertificateModel & certificate) {
                    try {
                        json jsonCertificate = {
                            {JsonKey::certificate, certificate.getOrignalCard()},
                            {JsonKey::signId, certificate.getSignId()},
                            {JsonKey::sign, VirgilBase64::encode(certificate.getSign())}
                        };
                        
                        return jsonCertificate.dump();
                        
                    } catch (std::exception& exception) {
                        throw std::logic_error(std::string("virgil-sdk:\n Marshaller<CertificateModel>::toOriginalJson ") +
                                               exception.what());
                    }
                }
                
                template <int INDENT = -1> static std::string toJson(const CertificateModel & certificate) {
                    try {
                        json jsonCertificate = {
                            {JsonKey::certificate, json::parse(Marshaller<CardModel>::toJson<INDENT>(certificate.getCard()))},
                            {JsonKey::signId, certificate.getSignId()},
                            {JsonKey::sign, VirgilBase64::encode(certificate.getSign())}
                        };
                        
                        return jsonCertificate.dump(INDENT);
                        
                    } catch (std::exception& exception) {
                        throw std::logic_error(std::string("virgil-sdk:\n Marshaller<CertificateModel>::toJson ") +
                                               exception.what());
                    }
                }
                
                template <int FAKE = 0> static CertificateModel fromJson(const std::string& jsonString) {
                    try {
                        json jsonCertificate = json::parse(jsonString);
                        
                        const std::string signId = jsonCertificate[JsonKey::signId];
                        const VirgilByteArray sign = VirgilBase64::decode(jsonCertificate[JsonKey::sign]);
                        
                        return CertificateModel(jsonCertificate[JsonKey::certificate].dump(),
                                                signId,
                                                sign);
                        
                    } catch (std::exception& exception) {
                        throw std::logic_error(std::string("virgil-sdk:\n Marshaller<CertificateModel>::fromJson ") +
                                               exception.what());
                    }
                }
                
            private:
                Marshaller(){};
            };
        }
    }
}

/**
 * Explicit methods instantiation
 */
template std::string
virgil::sdk::io::Marshaller<CertificateModel>::toJson(const CertificateModel&);

template std::string
virgil::sdk::io::Marshaller<CertificateModel>::toJson<2>(const CertificateModel&);

template std::string
virgil::sdk::io::Marshaller<CertificateModel>::toJson<4>(const CertificateModel&);

template CertificateModel
virgil::sdk::io::Marshaller<CertificateModel>::fromJson(const std::string&);
