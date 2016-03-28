#include <stdexcept>

#include <json.hpp>

#include <virgil/crypto/foundation/VirgilBase64.h>

#include "models/EncryptedMessageModel.h"

using json = nlohmann::json;

namespace vipm = virgil::IPMessaging;
namespace vcrypto = virgil::crypto;

vipm::models::EncryptedMessageModel::EncryptedMessageModel(const vcrypto::VirgilByteArray& encryptedMessage,
                                                           const vcrypto::VirgilByteArray& signature)
        : encryptedMessage_(encryptedMessage), signature_(signature) {
}

bool vipm::models::EncryptedMessageModel::isEmpty() const {
    return encryptedMessage_.empty() && signature_.empty();
}

vcrypto::VirgilByteArray vipm::models::EncryptedMessageModel::getMessage() const {
    return encryptedMessage_;
}

vcrypto::VirgilByteArray vipm::models::EncryptedMessageModel::getSignature() const {
    return signature_;
}

std::string vipm::models::toJson(const EncryptedMessageModel& model) {
    try {
        json jEncryptedMessageModel = {{"message", vcrypto::foundation::VirgilBase64::encode(model.getMessage())},
                                       {"sign", vcrypto::foundation::VirgilBase64::encode(model.getSignature())}};

        return jEncryptedMessageModel.dump(4);

    } catch (std::exception& exception) {
        throw std::logic_error(std::string("string toJson(EncryptedMessageModel) ") + exception.what());
    }
}

vipm::models::EncryptedMessageModel vipm::models::fromJson(const std::string& model) {
    try {
        json jEncryptedMessageModel = json::parse(model);
        std::string message = jEncryptedMessageModel["message"];
        std::string sign = jEncryptedMessageModel["sign"];

        return vipm::models::EncryptedMessageModel(vcrypto::foundation::VirgilBase64::decode(message),
                                                   vcrypto::foundation::VirgilBase64::decode(sign));

    } catch (std::exception& exception) {
        // throw std::logic_error(std::string("EncryptedMessageModel fromJson(string) ") + exception.what());
        return vipm::models::EncryptedMessageModel();
    }
}
