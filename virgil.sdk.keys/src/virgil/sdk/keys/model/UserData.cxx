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

#include <virgil/sdk/keys/model/UserData.h>
using virgil::sdk::keys::model::UserData;

#include <virgil/sdk/keys/model/PublicKey.h>
using virgil::sdk::keys::model::PublicKey;

UserData& UserData::accountId(const std::string& accountId) {
    accountId_ = accountId;
    return *this;
}

std::string UserData::accountId() const {
    return accountId_;
}

UserData& UserData::publicKeyId(const std::string& publicKeyId) {
    publicKeyId_ = publicKeyId;
    return *this;
}

std::string UserData::publicKeyId() const {
    return publicKeyId_;
}

UserData& UserData::userDataId(const std::string& userDataId) {
    userDataId_ = userDataId;
    return *this;
}

std::string UserData::userDataId() const {
    return userDataId_;
}

UserData& UserData::className(const std::string& className) {
    className_ = className;
    return *this;
}

std::string UserData::className() const {
    return className_;
}

UserData& UserData::type(const std::string& type) {
    type_ = type;
    return *this;
}

std::string UserData::type() const {
    return type_;
}

UserData& UserData::value(const std::string& value) {
    value_ = value;
    return *this;
}

std::string UserData::value() const {
    return value_;
}

UserData& UserData::isConfirmed(bool isConfirmed) {
    isConfirmed_ = isConfirmed;
    return *this;
}

bool UserData::isConfirmed() const {
    return isConfirmed_;
}

UserData& UserData::publicKey(const std::shared_ptr<PublicKey>& publicKey) {
    publicKey_ = publicKey;
    return *this;
}

std::shared_ptr<PublicKey> UserData::publicKey() const {
    return publicKey_;
}


bool UserData::operator==(const UserData& other) {
    return  (userDataId_  == other.userDataId_ ) &&
            (className_   == other.className_  ) &&
            (type_        == other.type_       ) &&
            (value_       == other.value_      ) &&
            (isConfirmed_ == other.isConfirmed_);
}

bool UserData::operator!=(const UserData& other) {
    return !this->operator==(other);
}
