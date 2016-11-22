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


#ifndef VIRGIL_SDK_VIRGILSDKERROR_H
#define VIRGIL_SDK_VIRGILSDKERROR_H

#include <limits>
#include <system_error>

#include <virgil/sdk/VirgilSDKException.h>

namespace virgil { namespace sdk {

/**
 * @brief Specific error codes for the sdk.
 * @ingroup Error
*/
enum class VirgilSDKError  {
    Reserved = 0, ///< Should not be used.
    VerificationFailed, ///< Verification of signature failed.
    Undefined = std::numeric_limits<int>::max()
};

/**
 * @brief This is specific error category that contains information about sdk errors.
 * @ingroup Error
 */
class VirgilSDKErrorCategory : public std::error_category {
public:
    /**
     * @return Category name.
     */
    const char* name() const noexcept override;

    /**
     *
     * @param ev Error value.
     * @return Error description for given error value.
     * @see VirgilSDKError for specific error values.
     */
    std::string message(int ev) const noexcept override;
};

/**
 * @brief Return singleton instance of the sdk error category.
 * @return Instance of the sdk error categoty.
 * @ingroup Error
 */
const VirgilSDKErrorCategory& sdk_category() noexcept;

/**
 * @brief Build exception with given error value and corresond error category.
 * @param ev Error value.
 * @return Exception with given error value and corresond error category.
 * @see VirgilSDKError for specific error values.
 * @ingroup Error
 */
inline VirgilSDKException make_error(VirgilSDKError ev) {
    return VirgilSDKException(static_cast<int>(ev), sdk_category());
}

/**
 * @brief Build exception with given error value and corresponding error category.
 * @param ev Error value.
 * @param what Additional error description.
 * @return Exception with given error value and corresond error category.
 * @see VirgilSDKError for specific error values.
 * @ingroup Error
 */
inline VirgilSDKException make_error(VirgilSDKError ev, const std::string& what) {
    return VirgilSDKException(static_cast<int>(ev), sdk_category(), what);
}

/**
 * @brief Build exception with given error value and corresponding error category.
 * @param ev Error value.
 * @param what Additional error description.
 * @return Exception with given error value and corresond error category.
 * @see VirgilSDKError for specific error values.
 * @ingroup Error
 */
inline VirgilSDKException make_error(VirgilSDKError ev, const char* what) {
    return VirgilSDKException(static_cast<int>(ev), sdk_category(), what);
}
}}

#endif //VIRGIL_SDK_VIRGILSDKERROR_H
