/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
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
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#ifndef VIRGIL_SDK_HTTP_CONNECTION_H
#define VIRGIL_SDK_HTTP_CONNECTION_H

#include <virgil/sdk/client/networking/Request.h>
#include <virgil/sdk/client/networking/Response.h>

namespace virgil {
    namespace sdk {
        namespace client {
            namespace networking {
                /**
                 * @brief This class encapsulates access to the HTTP layer.
                 * @note This class belongs to the **private** API
                 */
                class Connection {
                public:
                    /**
                     * @brief Send synchronous request.
                     * @param request - request to be send.
                     * @throw std::logic_error - if given parameters are inconsistent.
                     * @throw std::runtime_error - if error was occurred when send request.
                     */
                    virtual virgil::sdk::client::networking::Response send(const virgil::sdk::client::networking::Request &request);
                    
                    /**
                     * @brief Set custom CA bundle for TLS connection.
                     * @param request - request to be send.
                     * @throw std::logic_error - if given parameters are inconsistent.
                     * @throw std::runtime_error - if error was occurred when send request.
                     */
                    static void setCA(const std::string& ca);

                private:
                    static std::string customCA_;
                };
            }
        }
    }
}

#endif /* VIRGIL_SDK_HTTP_CONNECTION_H */