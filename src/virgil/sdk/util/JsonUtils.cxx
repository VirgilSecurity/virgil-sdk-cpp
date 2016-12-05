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


#include <virgil/sdk/Common.h>
#include <virgil/sdk/util/JsonUtils.h>

using nlohmann::json;

using virgil::sdk::util::JsonUtils;
using virgil::sdk::VirgilByteArray;

std::unordered_map<std::string, std::string> JsonUtils::jsonToUnorderedMap(const json &jsonObj) {
    std::unordered_map<std::string, std::string> res;

    for (auto it = jsonObj.begin(); it != jsonObj.end(); ++it) {
        res[it.key()] = it.value();
    }

    return res;
};

std::unordered_map<std::string, VirgilByteArray> JsonUtils::jsonToUnorderedBinaryMap(const json &jsonObj) {
    std::unordered_map<std::string, VirgilByteArray > res;

    for (auto it = jsonObj.begin(); it != jsonObj.end(); ++it) {
        res[it.key()] = VirgilBase64::decode(it.value());
    }

    return res;
};

json JsonUtils::unorderedMapToJson(const std::unordered_map<std::string, std::string> &map) {
    json j;

    for (auto it = map.begin(); it != map.end(); ++it) {
        j[it->first] = it->second;
    }

    return j;
}

json JsonUtils::unorderedBinaryMapToJson(const std::unordered_map<std::string, VirgilByteArray> &map) {
    json j;

    for (auto it = map.begin(); it != map.end(); ++it) {
        j[it->first] = VirgilBase64::encode(it->second);
    }

    return j;
}
