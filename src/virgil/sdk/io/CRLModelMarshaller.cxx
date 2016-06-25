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
#include <virgil/sdk/models/CRLElementModel.h>
#include <virgil/sdk/models/CRLModel.h>

using json = nlohmann::json;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::util::JsonKey;
using virgil::sdk::dto::Identity;
using virgil::sdk::models::CRLElementModel;
using virgil::sdk::models::CRLModel;

namespace virgil {
    namespace sdk {
        namespace io {
            
            std::string crlElementsToJson(const std::vector<CRLElementModel> & crlElements, const int INDENT);
            std::vector<CRLElementModel> crlElementsFromJson(const std::string& jsonStringCRLElements);
            
            /**
             * @brief Marshaller<CRLModel> specialization.
             */
            template <> class Marshaller<CRLModel> {
            public:
                template <int INDENT = -1> static std::string toJson(const CRLModel& crl) {
                    try {
                        json jsonCRL = {
                            {JsonKey::issuedAt, crl.getIssuedAt()},
                            {JsonKey::certificates, crlElementsToJson(crl.getElements(), INDENT)}
                        };
                        
                        return jsonCRL.dump(INDENT);
                        
                    } catch (std::exception& exception) {
                        throw std::logic_error(std::string("virgil-sdk:\n Marshaller<CRLModel>::toJson ") +
                                               exception.what());
                    }
                }
                
                template <int FAKE = 0> static CRLModel fromJson(const std::string& jsonString) {
                    try {
                        json jsonCRL = json::parse(jsonString);

                        std::string issuedAt = jsonCRL[JsonKey::issuedAt];
                        auto elements = crlElementsFromJson(jsonCRL[JsonKey::certificates].dump());
                        
                        return CRLModel(issuedAt, elements);
                        
                    } catch (std::exception& exception) {
                        throw std::logic_error(std::string("virgil-sdk:\n Marshaller<CRLModel>::fromJson ") +
                                               exception.what());
                    }
                }
                
            private:
                Marshaller(){};
            };
            
            std::string crlElementsToJson(const std::vector<CRLElementModel> & crlElements, const int INDENT) {
                try {
                    json jsonCRLElements = json::array();
                    for (const auto& element : crlElements) {
                        std::string jsonCRLElementStr = Marshaller<CRLElementModel>::toJson(element);
                        json jsonCRLElement = json::parse(jsonCRLElementStr);
                        jsonCRLElements.push_back(jsonCRLElement);
                    }
                    
                    return jsonCRLElements.dump(INDENT);
                } catch (std::exception& exception) {
                    throw std::logic_error(std::string("crlElementsToJson : ") + exception.what());
                }
            }
            
            std::vector<CRLElementModel> crlElementsFromJson(const std::string& jsonStringCRLElements) {
                try {
                    std::vector<CRLElementModel> res;
                    json jsonCRLElements = json::parse(jsonStringCRLElements);
                    std::vector<CRLElementModel> crlElements;
                    for (const auto& jsonElement : jsonCRLElements) {
                        CRLElementModel element = Marshaller<CRLElementModel>::fromJson(jsonElement.dump());
                        res.push_back(element);
                    }
                    
                    return res;
                    
                } catch (std::exception& exception) {
                    throw std::logic_error(std::string("crlElementsFromJson: ") + exception.what());
                }
            }
        }
    }
}

/**
 * Explicit methods instantiation
 */
template std::string
virgil::sdk::io::Marshaller<CRLModel>::toJson(const CRLModel&);

template std::string
virgil::sdk::io::Marshaller<CRLModel>::toJson<2>(const CRLModel&);

template std::string
virgil::sdk::io::Marshaller<CRLModel>::toJson<4>(const CRLModel&);

template CRLModel
virgil::sdk::io::Marshaller<CRLModel>::fromJson(const std::string&);
