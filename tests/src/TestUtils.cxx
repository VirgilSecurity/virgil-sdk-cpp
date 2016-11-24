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


#include <TestUtils.h>

using virgil::sdk::test::TestUtils;

CreateCardRequest TestUtils::instantiateCreateCardRequest() {
    return CreateCardRequest();
}
//
//let keyPair = self.crypto.generateKeyPair()
//let exportedPublicKey = self.crypto.export(keyPair.publicKey)
//
//// some random value
//let identityValue = UUID().uuidString
//let identityType = self.consts.applicationIdentityType
//let request = VSSCreateCardRequest(identity: identityValue, identityType: identityType, publicKey: exportedPublicKey)
//
//let privateAppKeyData = Data(base64Encoded: self.consts.applicationPrivateKeyBase64, options: Data.Base64DecodingOptions(rawValue: 0))!
//let appPrivateKey = self.crypto.importPrivateKey(from: privateAppKeyData, withPassword: self.consts.applicationPrivateKeyPassword)!
//
//let signer = VSSRequestSigner(crypto: self.crypto)
//
//try! signer.selfSign(request, with: keyPair.privateKey)
//try! signer.authoritySign(request, forAppId: self.consts.applicationId, with: appPrivateKey)
//
//return request;
