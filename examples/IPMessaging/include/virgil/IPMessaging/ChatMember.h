#ifndef CHAT_MEMBER_H
#define CHAT_MEMBER_H

#include <string>

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/sdk/models/CardModel.h>

namespace virgil {
namespace IPMessaging {

    class ChatMember {
    public:
        ChatMember() = default;

        ChatMember(const virgil::sdk::models::CardModel& card, const virgil::crypto::VirgilByteArray& privateKey);

        virgil::sdk::models::CardModel getCard() const;
        std::string getIdentity() const;
        virgil::crypto::VirgilByteArray getCardId() const;
        virgil::crypto::VirgilByteArray getPublicKey() const;
        virgil::crypto::VirgilByteArray getPrivateKey() const;

    private:
        virgil::sdk::models::CardModel card_;
        virgil::crypto::VirgilByteArray privateKey_;
    };
}
}

#endif
