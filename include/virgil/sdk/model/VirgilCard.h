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

#ifndef VIRGIL_SDK_MODEL_VIRGIL_CARD_H
#define VIRGIL_SDK_MODEL_VIRGIL_CARD_H

#include <string>
#include <vector>

#include <virgil/sdk/model/PublicKey.h>
#include <virgil/sdk/model/VirgilCardIdentity.h>

using PairStrStr = std::pair<std::string, std::string>;


namespace virgil { namespace sdk { namespace model {
    /**
     * @brief Data object represent "Virgil Card" entity.
     */
    class VirgilCard {
    public:
        VirgilCard() = default;

        VirgilCard(
                const bool confirme, 
                const std::string& id, 
                const std::string& createdAt, 
                const std::string& hash,
                const virgil::sdk::model::VirgilCardIdentity& identity,
                const std::vector<PairStrStr>& data,
                const virgil::sdk::model::PublicKey& publicKey
        );

        bool isConfirmed() const;
        std::string getId() const;
        std::string getCreatedAt() const;
        std::string getHash() const;
        virgil::sdk::model::VirgilCardIdentity getIdentity() const;
        std::vector<PairStrStr> getData() const;
        virgil::sdk::model::PublicKey getPublicKey() const;

        void setConfirme(const bool confirme);
        void setId(const std::string& id);
        void setCreatedAt(const std::string& createdAt);
        void setHash(const std::string& hash);
        void setIdentity(const virgil::sdk::model::VirgilCardIdentity& identity);
        void setData(const std::vector<PairStrStr>& data);
        void setPublicKey(const virgil::sdk::model::PublicKey& publicKey);

    private:
        bool confirme_ = false;
        std::string id_;
        std::string createdAt_;
        std::string hash_;
        virgil::sdk::model::VirgilCardIdentity identity_;
        std::vector<PairStrStr> data_;
        virgil::sdk::model::PublicKey publicKey_;
    };
}}}

#endif /* VIRGIL_SDK_MODEL_VIRGIL_CARD_H */
