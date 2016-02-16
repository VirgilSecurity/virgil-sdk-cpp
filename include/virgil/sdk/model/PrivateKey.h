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

#ifndef VIRGIL_SDK_MODEL_PRIVATE_KEY_H
#define VIRGIL_SDK_MODEL_PRIVATE_KEY_H

#include <string>

#include <virgil/crypto/VirgilByteArray.h>

namespace virgil {
namespace sdk {
    namespace model {
        /**
         * @brief Data object represent "Virgil Private Key" entity
         */
        class PrivateKey {
        public:
            /**
             * @brief Create epmpty private key
             */
            PrivateKey() = default;
            /**
             * @brief Creates private key with associated Virgil Card identifier
             *
             * @param virgilCardId - unique virgil card identifier defined by service
             * @param key - private kwy
             */
            PrivateKey(const std::string& virgilCardId, const virgil::crypto::VirgilByteArray& key);
            /**
             * @brief Return unique virgil card identifier
             */
            const std::string& getVirgilCardId() const;
            /**
             * @brief Return private key
             */
            const virgil::crypto::VirgilByteArray& getKey() const;

            /**
             * @brief Perform security cleanup
             *
             * @note This method should be called if private key is not needed anymore
             */
            void cleanup() noexcept;

            /**
             * @brief Perform security cleanup on destruction
             */
            virtual ~PrivateKey() noexcept;

        private:
            std::string virgilCardId_;
            virgil::crypto::VirgilByteArray key_;
        };

        inline bool operator==(const PrivateKey& left, const PrivateKey& right) {
            return left.getVirgilCardId() == right.getVirgilCardId() && left.getKey() == right.getKey();
        }

        inline bool operator!=(const PrivateKey& left, const PrivateKey& right) {
            return !(left == right);
        }
    }
}
}

#endif /* VIRGIL_SDK_MODEL_PRIVATE_KEY_H */
