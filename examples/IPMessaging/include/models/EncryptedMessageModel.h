#ifndef ENCRYPTED_MESSAGE_MODEL_H
#define ENCRYPTED_MESSAGE_MODEL_H

#include <string>

#include <virgil/crypto/VirgilByteArray.h>

namespace virgil {
namespace IPMessaging {
    namespace models {

        class EncryptedMessageModel {
        public:
            EncryptedMessageModel() = default;
            EncryptedMessageModel(const virgil::crypto::VirgilByteArray& encryptedMessage,
                                  const virgil::crypto::VirgilByteArray& signature);

            virgil::crypto::VirgilByteArray getMessage() const;
            virgil::crypto::VirgilByteArray getSignature() const;

            bool isEmpty() const;

        private:
            virgil::crypto::VirgilByteArray encryptedMessage_;
            virgil::crypto::VirgilByteArray signature_;
        };

        std::string toJson(const EncryptedMessageModel& encryptedMessageModel);
        EncryptedMessageModel fromJson(const std::string& encryptedMessageModel);
    }
}
}

#endif
