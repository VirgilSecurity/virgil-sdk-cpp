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

#include <virgil/sdk/VirgilSdkError.h>

using virgil::sdk::VirgilSdkErrorCategory;

const char* VirgilSdkErrorCategory::name() const noexcept {
    return "virgil/sdk";
}

std::string VirgilSdkErrorCategory::message(int ev) const noexcept {
    switch (static_cast<VirgilSdkError>(ev)) {
        case VirgilSdkError::VerificationFailed:
            return "Verification of signature failed.";
        case VirgilSdkError::CardVerificationFailed:
            return "Verification of Virgil Card failed.";
        case VirgilSdkError::ServiceQueryFailed:
            return "REST Query to Virgil Service failed.";
        case VirgilSdkError::AddSignatureFailed:
            return "Adding duplicate signature failed.";
        case VirgilSdkError::AddVerifierCredentialsFailed:
            return "Adding duplicate verifier credentials failed.";
        default:
            return "Undefined error.";
    }
}

const VirgilSdkErrorCategory& virgil::sdk::sdk_category() noexcept {
    static VirgilSdkErrorCategory inst;
    return inst;
}