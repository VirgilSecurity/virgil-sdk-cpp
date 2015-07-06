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

#ifndef VIRGIL_SDK_KEYS_HTTP_CONNECTION_DEFAULT_H
#define VIRGIL_SDK_KEYS_HTTP_CONNECTION_DEFAULT_H

#include <virgil/sdk/keys/http/ConnectionBase.h>

namespace virgil { namespace sdk { namespace keys { namespace http {

/**
 * @brief This abstract class unifies access to the HTTP layer.
 */
class Connection final : public ConnectionBase {
    public:
        /**
         * @brief Configure connection with base address URI.
         * @param appToken - application specific key that is used for all service communications.
         * @param baseAddress - service base address including API version, i.e. https://keys.virgilsecurity.com/v1
         */
        explicit Connection(const std::string& appToken, const std::string& baseAddress = baseAddressDefault);
        /**
         * @brief Return application specific key.
         */
        std::string appToken() const;
        /**
         * @name Default class implementation.
         */
        //@{
        Response send(const Request& request) override;
        void checkResponseError(const Response& response, PkiError::Action action) override;
        //@}
    private:
        std::string appToken_;
    };

}}}}

#endif /* VIRGIL_SDK_KEYS_HTTP_CONNECTION_DEFAULT_H */

