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

#include <virgil/sdk/keys/util/JsonKey.h>
using virgil::sdk::keys::util::JsonKey;

const std::string JsonKey::publicKey = "public_key";
const std::string JsonKey::publicKeys = "public_keys";
const std::string JsonKey::userData = "user_data";
const std::string JsonKey::className = "class";
const std::string JsonKey::type = "type";
const std::string JsonKey::value = "value";
const std::string JsonKey::isConfirmed = "is_confirmed";
const std::string JsonKey::confirmationCode = "confirmation_code";
const std::string JsonKey::error = "error";
const std::string JsonKey::errorCode = "code";
const std::string JsonKey::id = "id";
const std::string JsonKey::accountId = "account_id";
const std::string JsonKey::publicKeyId = "public_key_id";
const std::string JsonKey::userDataId = "user_data_id";
const std::string JsonKey::expanded = "expanded";
const std::string JsonKey::uuid = "request_sign_uuid";
const std::string JsonKey::uuidSign = "uuid_sign";
