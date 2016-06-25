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

using json = nlohmann::json;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::VirgilBase64;

using virgil::sdk::util::JsonKey;
using virgil::sdk::dto::Identity;
using virgil::sdk::models::CRLElementModel;

namespace virgil {
    namespace sdk {
        namespace io {
            /**
             * @brief Marshaller<CRLElementModel> specialization.
             */
            template <> class Marshaller<CRLElementModel> {
            public:
                template <int INDENT = -1> static std::string toJson(const CRLElementModel& element) {
                    try {
                        json jsonCRLElement = {
                            {JsonKey::id, element.getId()},
                            {JsonKey::revokedAt, element.getRevokedAt()},
                            {JsonKey::identityType, element.getIdentity().getType()},
                            {JsonKey::identityValue, element.getIdentity().getValue()},
                        };
                        
                        return jsonCRLElement.dump(INDENT);
                        
                    } catch (std::exception& exception) {
                        throw std::logic_error(std::string("virgil-sdk:\n Marshaller<CRLElementModel>::toJson ") +
                                               exception.what());
                    }
                }
                
                template <int FAKE = 0> static CRLElementModel fromJson(const std::string& jsonString) {
                    try {
                        json jsonCRLElement = json::parse(jsonString);
                        
                        std::string id = jsonCRLElement[JsonKey::id];
                        std::string revokedAt = jsonCRLElement[JsonKey::revokedAt];
                        std::string identityType = jsonCRLElement[JsonKey::identityType];
                        std::string identityValue = jsonCRLElement[JsonKey::identityValue];
                        
                        return CRLElementModel(id, revokedAt, Identity(identityValue, identityType));
                        
                    } catch (std::exception& exception) {
                        throw std::logic_error(std::string("virgil-sdk:\n Marshaller<CRLElementModel>::fromJson ") +
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
virgil::sdk::io::Marshaller<CRLElementModel>::toJson(const CRLElementModel&);

template std::string
virgil::sdk::io::Marshaller<CRLElementModel>::toJson<2>(const CRLElementModel&);

template std::string
virgil::sdk::io::Marshaller<CRLElementModel>::toJson<4>(const CRLElementModel&);

template CRLElementModel
virgil::sdk::io::Marshaller<CRLElementModel>::fromJson(const std::string&);
