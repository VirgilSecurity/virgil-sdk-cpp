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


#ifndef VIRGIL_SDK_SIGNABLEREQUEST_H
#define VIRGIL_SDK_SIGNABLEREQUEST_H

#include <virgil/sdk/Common.h>
#include <virgil/sdk/client/models/serialization/CanonicalSerializer.h>
#include <virgil/sdk/client/models/interfaces/SignableRequestInterface.h>
#include <virgil/sdk/client/models/interfaces/Exportable.h>
#include <virgil/sdk/client/models/interfaces/Importable.h>

#include <unordered_map>
#include <string>

namespace virgil {
namespace sdk {
namespace client {
namespace models {
    namespace requests {
        template <typename SnapshotModelType, typename DerivedClass>
        class SignableRequest : public interfaces::SignableRequestInterface,
                                public interfaces::Exportable,
                                public interfaces::Importable<DerivedClass> {
        public:
            const VirgilByteArray& snapshot() const override { return snapshot_; }

            void addSignature(VirgilByteArray signature, std::string fingerprint) override {
                signatures_[std::move(fingerprint)] = std::move(signature);
            }

            const std::unordered_map<std::string, VirgilByteArray>& signatures() const override { return signatures_; };
            const SnapshotModelType& snapshotModel() const { return snapshotModel_; }

            std::string exportAsString() const override;

        protected:
            SignableRequest(
                    const SnapshotModelType &snapshotModel,
                    const std::unordered_map<std::string, VirgilByteArray> &signatures = {})
                    : SignableRequest<SnapshotModelType, DerivedClass>(
                        serialization::CanonicalSerializer<SnapshotModelType>::toCanonicalForm(snapshotModel),
                        snapshotModel, signatures) { };

            SignableRequest(
                    VirgilByteArray snapshot,
                    SnapshotModelType snapshotModel,
                    std::unordered_map<std::string, VirgilByteArray> signatures)
                    : snapshot_(std::move(snapshot)),
                      snapshotModel_(std::move(snapshotModel)),
                      signatures_(std::move(signatures)) { };

        private:
            VirgilByteArray snapshot_;
            SnapshotModelType snapshotModel_;
            std::unordered_map<std::string, VirgilByteArray> signatures_;
        };
    }
}
}
}
}

#endif //VIRGIL_SDK_SIGNABLEREQUEST_H
