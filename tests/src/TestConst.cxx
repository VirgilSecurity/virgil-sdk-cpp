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


#include <TestConst.h>

using virgil::sdk::test::TestConst;

std::string TestConst::applicationToken() const {
    return "AT.931f8eb623be4e4709cbc241bfc89dde3a518527faccf2e1da7f9bd1a71fe78b";
}

std::string TestConst::applicationPublicKeyBase64() const {
    return "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1Db3dCUVlESzJWd0F5RUExblJKZHpWeDVDcE10VGJjbTNLZVk1b3Q2OU5OV3lNTjV1cDNRbDE1N1ZJPQ0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tDQo=";
}

std::string TestConst::applicationPrivateKeyBase64() const {
    return "LS0tLS1CRUdJTiBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQ0KTUlHaE1GMEdDU3FHU0liM0RRRUZEVEJRTUM4R0NTcUdTSWIzRFFFRkREQWlCQkRROWFBSHdRbjFXckxlMDN5Sw0KR2R0aEFnSVJpakFLQmdncWhraUc5dzBDQ2pBZEJnbGdoa2dCWlFNRUFTb0VFTXhwQTNzVVVaMXlWR1V2VWVTTA0KUmE4RVFKcHVZOXV1eCs2d0NVSno0Ti9qVnZ2WmRPMTdmcnAwMytYZWhxN1ZhbUNwK0Y1RFE1cS82M2tGV0drMw0KcXA4Wk5GQlZ4VEpKY1grRkFLVGIvc0VGTnhFPQ0KLS0tLS1FTkQgRU5DUllQVEVEIFBSSVZBVEUgS0VZLS0tLS0NCg==";
}

std::string TestConst::applicationPrivateKeyPassword() const {
    return "test";
}

std::string TestConst::applicationIdentityType() const {
    return "test";
}

std::string TestConst::applicationId() const {
    return "c53035253366736218ea3ebc924275073aafc2e78d09fe4f910e6b33a7297dd7";
}
