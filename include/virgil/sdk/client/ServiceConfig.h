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

#ifndef VIRGIL_SDK_SERVICECONFIG_H
#define VIRGIL_SDK_SERVICECONFIG_H

#include <virgil/sdk/client/interfaces/CardValidatorInterface.h>

namespace virgil {
namespace sdk {
    namespace client {
        /*!
         * @brief This class is Container for data needed to setup Client
         * @see Client
         */
        class ServiceConfig {
        public:
            /*!
             * @brief Creates config with given token and default value
             * @note Default ServiceConfig doesn't use any card validation @see CardValidatorInterface
             * @param token
             * @return ServiceConfig instance with given token and default values
             */
            static ServiceConfig createConfig(const std::string &token);

            /*! @brief Setter.
             * @param token std::string to be set
             * @return current ServiceConfig instance
             */
            ServiceConfig& token(std::string token);

            /*! @brief Setter.
             * @param token std::string with url of cards service (includes base url, version and /)
             * @note This url is used for endpoints capable to perform both read and write operations
             * @return current ServiceConfig instance
             */
            ServiceConfig& cardsServiceURL(std::string cardsServiceURL);

            /*! @brief Setter.
             * @param token std::string with url of cards service (includes base url, version and /)
             * @note This url is used for endpoints capable to perform only read.
             *       Don't use read/write url cause this can lead to performance issues
             * @return current ServiceConfig instance
             */
            ServiceConfig& cardsServiceROURL(std::string cardsServiceROURL);

            /*!
             * @brief Setter.
             * @param validator std::unique_ptr with CardValidator implementation
             * @note Can be null
             * @return current ServiceConfig instance
             */
            ServiceConfig& cardValidator(std::unique_ptr<interfaces::CardValidatorInterface> validator);

            /*!
             * @brief Getter.
             * @return std::string with token.
             */
            const std::string& token() const { return token_; }

            /*!
             * @brief Getter.
             * @return std::string with cards service URL.
             */
            const std::string& cardsServiceURL() const { return cardsServiceURL_; }

            /*!
             * @brief Getter.
             * @return std::string with cards service read only URL.
             */
            const std::string& cardsServiceROURL() const { return cardsServiceROURL_; }

            /*!
             * @brief Getter.
             * @note Can be null
             * @return std::unique_ptr with CardValidator interface.
             */
            const std::unique_ptr<interfaces::CardValidatorInterface>& cardValidator() const { return validator_; }

        private:
            ServiceConfig(std::string token);

            std::string token_;
            std::string cardsServiceURL_;
            std::string cardsServiceROURL_;
            std::unique_ptr<interfaces::CardValidatorInterface> validator_;
        };
    }
}
}

#endif //VIRGIL_SDK_SERVICECONFIG_H
