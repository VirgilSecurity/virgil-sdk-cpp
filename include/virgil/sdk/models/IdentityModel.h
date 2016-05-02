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

#ifndef VIRGIL_SDK_MODELS_IDENTITY_MODEL_H
#define VIRGIL_SDK_MODELS_IDENTITY_MODEL_H

#include <string>

namespace virgil {
namespace sdk {
    namespace models {
        /**
         * @brief This class reresents extended version of class Identity
         *
         * @details This class contains addition information of identity,
         *          that is used in conjuction with class @link CardModel @endlink.
         */
        class IdentityModel {
        public:
            /**
             * @brief Enumerate possible identity types
             */
            enum class Type {
                None,        // Identity is undefined
                Email,       // Identity is email
                Application, // Identity is application
                Custom       // Identity is custom
            };

        public:
            /**
             * @brief Creates not valid identity
             */
            IdentityModel() = default;
            /**
             * @brief Creates valid identity
             *
             * @param id - unique object identifier defined by service
             * @param createdAt - cretion date timestamp defined by service
             * @param confirmed - true, if identity is confirmed by user
             * @param value - identity value
             * @param type - identity type
             */
            IdentityModel(
                const std::string& id, const std::string& createdAt, const bool authorizedBy, const std::string& value,
                const virgil::sdk::models::IdentityModel::Type& type = virgil::sdk::models::IdentityModel::Type::None);
            /**
             * @brief Return unique object identifier defined by service
             */
            const std::string getId() const;
            /**
             * @brief Return cretion date timestamp defined by service
             */
            const std::string getCreatedAt() const;
            /**
             * @brief Return true, if identity is confirmed by user, false - otherwise
             */
            bool authorizedBy() const;
            /**
             * @brief Return identity value
             */
            const std::string getValue() const;
            /**
             * @brief Return identity type
             */
            const virgil::sdk::models::IdentityModel::Type getType() const;

        private:
            std::string id_;
            std::string createdAt_;
            bool authorizedBy_ = false;
            std::string value_;
            IdentityModel::Type type_ = IdentityModel::Type::None;
        };
        /**
         * @brief Return string representation of the identity type
         */
        std::string toString(const virgil::sdk::models::IdentityModel::Type& identityType);
        /**
         * @brief Use string representation to construct identity type
         */
        virgil::sdk::models::IdentityModel::Type fromString(const std::string& identityType);

        /**
         * @brief Compare identities for equality
         *
         * @return true if given objects are equal, false - otherwise
         */
        inline bool operator==(const IdentityModel& left, const IdentityModel& right) {
            return left.getId() == right.getId() && left.getCreatedAt() == right.getCreatedAt() &&
                   left.authorizedBy() == right.authorizedBy() && left.getValue() == right.getValue() &&
                   left.getType() == right.getType();
        }

        /**
         * @brief Compare identities for inequality
         *
         * @return true if given objects are inequal, false - otherwise
         */
        inline bool operator!=(const IdentityModel& left, const IdentityModel& right) {
            return !(left == right);
        }
    }
}
}

#endif /* VIRGIL_SDK_MODELS_IDENTITY_MODEL_H */
